// Package protocol содержит независимые от сетевого движка типы протокола
// WireGuard/AmneziaWG и алгоритмы выбора маршрута.
package protocol

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

// Route описывает сеть назначения и пир, через который следует отправлять трафик.
// Priority используется только для выбора между маршрутами с одинаковым префиксом.
type Route struct {
	Prefix   netip.Prefix `json:"prefix"`
	Peer     string       `json:"peer"`
	Priority int          `json:"priority,omitempty"`
}

// Normalize проверяет маршрут и приводит сеть к канонической форме.
func (r Route) Normalize() (Route, error) {
	if !r.Prefix.IsValid() {
		return Route{}, errors.New("маршрут содержит некорректный префикс")
	}
	if r.Peer == "" {
		return Route{}, errors.New("для маршрута не указан пир")
	}
	r.Prefix = r.Prefix.Masked()
	return r, nil
}

// RouteTable — потокобезопасная таблица маршрутов.
// Внутри одной сети побеждает маршрут с большим Priority; при равенстве
// приоритетов используется лексикографически меньший идентификатор пира.
// Между разными длинами префикса всегда побеждает наиболее специфичный маршрут.
type RouteTable struct {
	mu     sync.RWMutex
	routes map[string]Route
}

func NewRouteTable() *RouteTable {
	return &RouteTable{routes: make(map[string]Route)}
}

func routeKey(r Route) string {
	return r.Prefix.String() + "|" + r.Peer
}

// Add добавляет или атомарно заменяет маршрут для пары сеть/пир.
func (t *RouteTable) Add(route Route) error {
	r, err := route.Normalize()
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes[routeKey(r)] = r
	return nil
}

// Remove удаляет маршрут сети для указанного пира. Возвращает true, если он был найден.
func (t *RouteTable) Remove(prefix netip.Prefix, peer string) bool {
	if !prefix.IsValid() || peer == "" {
		return false
	}
	key := prefix.Masked().String() + "|" + peer
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.routes[key]; !ok {
		return false
	}
	delete(t.routes, key)
	return true
}

// Lookup выполняет longest-prefix match. Приоритет учитывается лишь у
// кандидатов с одинаковой длиной префикса.
func (t *RouteTable) Lookup(addr netip.Addr) (Route, bool) {
	if !addr.IsValid() {
		return Route{}, false
	}
	if addr.Is4In6() { addr = addr.Unmap() }
	t.mu.RLock()
	defer t.mu.RUnlock()

	var best Route
	found := false
	for _, candidate := range t.routes {
		if candidate.Prefix.Addr().Is4() != addr.Is4() || !candidate.Prefix.Contains(addr) {
			continue
		}
		if !found || candidate.Prefix.Bits() > best.Prefix.Bits() ||
			(candidate.Prefix.Bits() == best.Prefix.Bits() && betterTie(candidate, best)) {
			best, found = candidate, true
		}
	}
	return best, found
}

func betterTie(a, b Route) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	return a.Peer < b.Peer
}

// Snapshot возвращает стабильную копию таблицы, отсортированную для воспроизводимости.
func (t *RouteTable) Snapshot() []Route {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Route, 0, len(t.routes))
	for _, r := range t.routes {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefix != out[j].Prefix {
			if out[i].Prefix.Addr().Is4() != out[j].Prefix.Addr().Is4() {
				return out[i].Prefix.Addr().Is4()
			}
			if out[i].Prefix.Bits() != out[j].Prefix.Bits() {
				return out[i].Prefix.Bits() > out[j].Prefix.Bits()
			}
			return out[i].Prefix.String() < out[j].Prefix.String()
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Peer < out[j].Peer
	})
	return out
}

// Replace атомарно заменяет всё содержимое таблицы. При ошибке исходная
// таблица остаётся неизменной.
func (t *RouteTable) Replace(routes []Route) error {
	next := make(map[string]Route, len(routes))
	for _, route := range routes {
		r, err := route.Normalize()
		if err != nil {
			return fmt.Errorf("ошибка маршрута %q: %w", route.Prefix, err)
		}
		next[routeKey(r)] = r
	}
	t.mu.Lock()
	t.routes = next
	t.mu.Unlock()
	return nil
}

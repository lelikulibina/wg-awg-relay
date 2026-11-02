// Package linux реализует управление маршрутами Linux через iproute2.
package linux

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return out, err
}

type RouteManager struct {
	mu sync.Mutex
	iface string
	runner Runner
	current map[string]netip.Prefix
}

func NewRouteManager(iface string, runner Runner) (*RouteManager, error) {
	if strings.TrimSpace(iface) == "" || iface != strings.TrimSpace(iface) || len(iface) > 15 {
		return nil, errors.New("имя Linux-интерфейса должно содержать от 1 до 15 символов без пробелов по краям")
	}
	if strings.ContainsAny(iface, "/\t\r\n ") { return nil, errors.New("недопустимое имя Linux-интерфейса") }
	if runner == nil { runner = ExecRunner{} }
	return &RouteManager{iface:iface, runner:runner, current:make(map[string]netip.Prefix)}, nil
}

func (m *RouteManager) Add(ctx context.Context, prefix netip.Prefix) error {
	if !prefix.IsValid() { return errors.New("некорректный маршрут") }
	prefix = prefix.Masked()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.addLocked(ctx, prefix); err != nil { return err }
	m.current[prefix.String()] = prefix
	return nil
}

func (m *RouteManager) Remove(ctx context.Context, prefix netip.Prefix) error {
	if !prefix.IsValid() { return errors.New("некорректный маршрут") }
	prefix = prefix.Masked()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.removeLocked(ctx, prefix); err != nil { return err }
	delete(m.current, prefix.String())
	return nil
}

// Apply performs an add-before-remove transition. New routes are installed
// before obsolete routes are deleted, minimizing forwarding interruptions.
// On failure it attempts to restore the previous route set.
func (m *RouteManager) Apply(ctx context.Context, prefixes []netip.Prefix) error {
	next := make(map[string]netip.Prefix, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() { return errors.New("список содержит некорректный маршрут") }
		prefix = prefix.Masked()
		next[prefix.String()] = prefix
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var added, removed []netip.Prefix
	for _, entry := range sortedPrefixes(next) {
		key, prefix := entry.key, entry.prefix
		if _, exists := m.current[key]; exists { continue }
		if err := m.addLocked(ctx, prefix); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for i := len(added)-1; i >= 0; i-- { _ = m.removeLocked(rollbackCtx, added[i]) }
			return fmt.Errorf("не удалось добавить маршрут %s: %w", prefix, err)
		}
		added = append(added, prefix)
	}
	for _, entry := range sortedPrefixes(m.current) {
		key, prefix := entry.key, entry.prefix
		if _, exists := next[key]; exists { continue }
		if err := m.removeLocked(ctx, prefix); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var rollbackErr error
			for i := len(removed)-1; i >= 0; i-- {
				if restoreErr := m.addLocked(rollbackCtx, removed[i]); restoreErr != nil {
					rollbackErr = errors.Join(rollbackErr, restoreErr)
				}
			}
			for i := len(added)-1; i >= 0; i-- {
				if removeErr := m.removeLocked(rollbackCtx, added[i]); removeErr != nil {
					rollbackErr = errors.Join(rollbackErr, removeErr)
				}
			}
			if rollbackErr != nil { return errors.Join(fmt.Errorf("не удалось удалить маршрут %s: %w", prefix, err), fmt.Errorf("ошибка отката: %w", rollbackErr)) }
			return fmt.Errorf("не удалось удалить маршрут %s; исходный набор восстановлен: %w", prefix, err)
		}
		removed = append(removed, prefix)
	}
	m.current = next
	return nil
}

func (m *RouteManager) Snapshot() []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]netip.Prefix, 0, len(m.current))
	for _, prefix := range m.current { out = append(out, prefix) }
	sort.Slice(out, func(i,j int) bool {
		if out[i].Addr().Is4() != out[j].Addr().Is4() { return out[i].Addr().Is4() }
		if out[i].Bits() != out[j].Bits() { return out[i].Bits() > out[j].Bits() }
		return out[i].String() < out[j].String()
	})
	return out
}

func (m *RouteManager) addLocked(ctx context.Context, prefix netip.Prefix) error {
	family := "-6"
	if prefix.Addr().Is4() { family = "-4" }
	out, err := m.runner.Run(ctx, "ip", family, "route", "replace", prefix.String(), "dev", m.iface)
	if err != nil { return fmt.Errorf("iproute2: %s", strings.TrimSpace(string(out))) }
	return nil
}

func (m *RouteManager) removeLocked(ctx context.Context, prefix netip.Prefix) error {
	family := "-6"
	if prefix.Addr().Is4() { family = "-4" }
	out, err := m.runner.Run(ctx, "ip", family, "route", "del", prefix.String(), "dev", m.iface)
	if err != nil {
		message := strings.TrimSpace(string(out))
		if strings.Contains(message, "No such process") { return nil }
		return fmt.Errorf("iproute2: %s", message)
	}
	return nil
}

func sortedPrefixes(values map[string]netip.Prefix) []struct {
	key string
	prefix netip.Prefix
} {
	out := make([]struct { key string; prefix netip.Prefix }, 0, len(values))
	for key, prefix := range values { out = append(out, struct { key string; prefix netip.Prefix }{key, prefix}) }
	sort.Slice(out, func(i,j int) bool { return out[i].prefix.String() < out[j].prefix.String() })
	return out
}

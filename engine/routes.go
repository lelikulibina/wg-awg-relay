// Package engine synchronizes the route model with a running AmneziaWG device.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/lelikulibina/wg-awg-relay/protocol"
)

type RouteController struct {
	mu      sync.Mutex
	config  protocol.Config
	table   *protocol.RouteTable
	uapi    protocol.UAPIClient
	applied bool
}

func NewRouteController(cfg protocol.Config, client protocol.UAPIClient) (*RouteController, error) {
	if err := cfg.Validate(); err != nil { return nil, err }
	routes, err := cfg.EffectiveRoutes()
	if err != nil { return nil, err }
	table := protocol.NewRouteTable()
	if err := table.Replace(routes); err != nil { return nil, err }
	return &RouteController{config: cloneConfig(cfg), table: table, uapi: client}, nil
}

// ApplyInitial applies the complete device configuration once. Subsequent
// route changes use per-peer UAPI operations and never replace all peers.
func (c *RouteController) ApplyInitial(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.applied { return errors.New("начальная конфигурация уже применена") }
	request, err := protocol.BuildUAPIConfig(c.config)
	if err != nil { return err }
	if err := c.uapi.Apply(ctx, request); err != nil { return err }
	routes, err := c.config.EffectiveRoutes()
	if err != nil { return err }
	if err := c.table.Replace(routes); err != nil { return err }
	c.applied = true
	return nil
}

func (c *RouteController) AddRoute(ctx context.Context, route protocol.Route) error {
	normalized, err := route.Normalize()
	if err != nil { return err }
	c.mu.Lock()
	defer c.mu.Unlock()
	next := cloneConfig(c.config)
	peerExists := false
	for _, peer := range next.Peers { if peer.Name == normalized.Peer { peerExists = true; break } }
	if !peerExists { return fmt.Errorf("неизвестный пир %q", normalized.Peer) }
	replaced := false
	for i := range next.Routes {
		prefix, parseErr := netip.ParsePrefix(next.Routes[i].Prefix)
		if parseErr == nil && prefix.Masked() == normalized.Prefix && next.Routes[i].Peer == normalized.Peer {
			next.Routes[i].Priority = normalized.Priority
			replaced = true
			break
		}
	}
	if !replaced {
		next.Routes = append(next.Routes, protocol.RouteConfig{
			Prefix: normalized.Prefix.String(), Peer: normalized.Peer, Priority: normalized.Priority,
		})
	}
	return c.commitConfig(ctx, next)
}

func (c *RouteController) RemoveRoute(ctx context.Context, prefix netip.Prefix, peer string) error {
	if !prefix.IsValid() || peer == "" { return errors.New("для удаления требуется корректный префикс и имя пира") }
	prefix = prefix.Masked()
	c.mu.Lock()
	defer c.mu.Unlock()
	next := cloneConfig(c.config)
	removed := false
	global := next.Routes[:0]
	for _, route := range next.Routes {
		p, err := netip.ParsePrefix(route.Prefix)
		if err == nil && p.Masked() == prefix && route.Peer == peer { removed = true; continue }
		global = append(global, route)
	}
	next.Routes = global
	for i := range next.Peers {
		if next.Peers[i].Name != peer { continue }
		routes := next.Peers[i].Routes[:0]
		for _, route := range next.Peers[i].Routes {
			p, err := netip.ParsePrefix(route.Prefix)
			if err == nil && p.Masked() == prefix { removed = true; continue }
			routes = append(routes, route)
		}
		next.Peers[i].Routes = routes
	}
	if !removed { return fmt.Errorf("маршрут %s для пира %q не найден", prefix, peer) }
	return c.commitConfig(ctx, next)
}

func (c *RouteController) commitConfig(ctx context.Context, next protocol.Config) error {
	if err := next.Validate(); err != nil { return err }
	newRoutes, err := next.EffectiveRoutes()
	if err != nil { return err }
	if !c.applied {
		if err := c.table.Replace(newRoutes); err != nil { return err }
		c.config = next
		return nil
	}

	plan, err := makeUpdatePlan(c.config, next)
	if err != nil { return err }
	attempted := make([]peerUpdate, 0, len(plan))
	for _, update := range plan {
		request, err := protocol.BuildPeerUAPI(update.peer, update.next)
		if err != nil { return err }
		attempted = append(attempted, update)
		if err := c.uapi.Apply(ctx, request); err != nil {
			rollbackErr := c.rollback(attempted)
			if rollbackErr != nil { return errors.Join(fmt.Errorf("не удалось обновить маршруты: %w", err), fmt.Errorf("ошибка отката: %w", rollbackErr)) }
			return fmt.Errorf("не удалось обновить маршруты; исходная конфигурация восстановлена: %w", err)
		}
	}
	if err := c.table.Replace(newRoutes); err != nil {
		rollbackErr := c.rollback(attempted)
		if rollbackErr != nil { return errors.Join(err, rollbackErr) }
		return err
	}
	c.config = next
	return nil
}

type peerUpdate struct {
	peer protocol.Peer
	old  []netip.Prefix
	next []netip.Prefix
	gains bool
}

func makeUpdatePlan(oldConfig, newConfig protocol.Config) ([]peerUpdate, error) {
	plan := make([]peerUpdate, 0)
	for _, peer := range newConfig.Peers {
		oldIPs, err := oldConfig.PeerAllowedIPs(peer.Name)
		if err != nil { return nil, err }
		newIPs, err := newConfig.PeerAllowedIPs(peer.Name)
		if err != nil { return nil, err }
		if samePrefixes(oldIPs, newIPs) { continue }
		oldSet := prefixSet(oldIPs)
		gains := false
		for _, prefix := range newIPs { if _, ok := oldSet[prefix.String()]; !ok { gains = true; break } }
		plan = append(plan, peerUpdate{peer:peer, old:oldIPs, next:newIPs, gains:gains})
	}
	sort.Slice(plan, func(i,j int) bool {
		if plan[i].gains != plan[j].gains { return plan[i].gains }
		return plan[i].peer.Name < plan[j].peer.Name
	})
	return plan, nil
}

func (c *RouteController) rollback(attempted []peerUpdate) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result error
	for i := len(attempted)-1; i >= 0; i-- {
		update := attempted[i]
		request, err := protocol.BuildPeerUAPI(update.peer, update.old)
		if err == nil { err = c.uapi.Apply(ctx, request) }
		if err != nil { result = errors.Join(result, fmt.Errorf("пир %q: %w", update.peer.Name, err)) }
	}
	return result
}

func (c *RouteController) Lookup(addr netip.Addr) (protocol.Route, bool) {
	return c.table.Lookup(addr)
}

func (c *RouteController) Snapshot() []protocol.Route {
	return c.table.Snapshot()
}

func (c *RouteController) Config() protocol.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneConfig(c.config)
}

func (c *RouteController) Applied() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applied
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) { return false }
	left, right := prefixSet(a), prefixSet(b)
	if len(left) != len(right) { return false }
	for prefix := range left { if _, ok := right[prefix]; !ok { return false } }
	return true
}

func prefixSet(prefixes []netip.Prefix) map[string]struct{} {
	out := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes { out[prefix.Masked().String()] = struct{}{} }
	return out
}

func cloneConfig(cfg protocol.Config) protocol.Config {
	out := cfg
	out.Address = append([]string(nil), cfg.Address...)
	out.Routes = append([]protocol.RouteConfig(nil), cfg.Routes...)
	out.Peers = make([]protocol.Peer, len(cfg.Peers))
	for i, peer := range cfg.Peers {
		out.Peers[i] = peer
		out.Peers[i].AllowedIPs = append([]string(nil), peer.AllowedIPs...)
		out.Peers[i].Routes = append([]protocol.RouteConfig(nil), peer.Routes...)
	}
	if cfg.AmneziaWG != nil {
		awg := *cfg.AmneziaWG
		if cfg.AmneziaWG.RandomTrailers != nil { v := *cfg.AmneziaWG.RandomTrailers; awg.RandomTrailers = &v }
		if cfg.AmneziaWG.DisableCookies != nil { v := *cfg.AmneziaWG.DisableCookies; awg.DisableCookies = &v }
		out.AmneziaWG = &awg
	}
	return out
}

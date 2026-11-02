package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/lelikulibina/wg-awg-relay/engine"
	"github.com/lelikulibina/wg-awg-relay/platform/linux"
	"github.com/lelikulibina/wg-awg-relay/protocol"
)

type Options struct {
	BinaryPath string
	InterfaceName string
	SocketPath string
	Runner linux.Runner
}

type Service struct {
	mu sync.Mutex
	process *linux.DeviceProcess
	uapi protocol.UAPIClient
	link *linux.LinkManager
	routes *linux.RouteManager
	nat *linux.NATManager
	forwarding *linux.ForwardingManager
	controller *engine.RouteController
	started bool
	stopped bool
}

func New(cfg protocol.Config, options Options) (*Service, error) {
	if err := cfg.Validate(); err != nil { return nil, err }
	if cfg.FwMark == 0 { cfg.FwMark = 51820 }
	if options.BinaryPath == "" { options.BinaryPath = "amneziawg-go" }
	if options.InterfaceName == "" { options.InterfaceName = "awg0" }
	process, err := linux.NewDeviceProcess(options.BinaryPath, options.InterfaceName, options.SocketPath)
	if err != nil { return nil, err }
	client := protocol.UAPIClient{SocketPath:process.SocketPath()}
	controller, err := engine.NewRouteController(cfg, client)
	if err != nil { return nil, err }
	link, err := linux.NewLinkManager(options.InterfaceName, options.Runner)
	if err != nil { return nil, err }
	routes, err := linux.NewRouteManagerWithPolicy(options.InterfaceName, cfg.FwMark, cfg.FwMark, options.Runner)
	if err != nil { return nil, err }
	nat, err := linux.NewNATManager(options.InterfaceName, options.Runner)
	if err != nil { return nil, err }
	return &Service{
		process:process, uapi:client, link:link, routes:routes,
		nat:nat, forwarding:linux.NewForwardingManager(options.Runner), controller:controller,
	}, nil
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started { return errors.New("релей уже запущен") }
	if s.stopped { return errors.New("остановленный экземпляр релея нельзя запустить повторно; создайте новый Service") }
	if err := s.process.Start(ctx); err != nil { return err }
	cleanup := func(cause error) error {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = s.routes.Apply(cleanupCtx, nil)
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if stopErr := s.process.Stop(stopCtx); stopErr != nil { s.stopped = true; return errors.Join(cause, stopErr) }
		s.stopped = true
		return cause
	}
	desired := s.controller.Config()
	if err := s.link.Configure(ctx, desired.Address, desired.MTU); err != nil { return cleanup(err) }
	effective, err := desired.EffectiveRoutes()
	if err != nil { return cleanup(err) }
	ipv6 := hasIPv6(s.config.Address, effective)
	if err := s.forwarding.Enable(ctx, ipv6); err != nil { return cleanup(err) }
	if desired.NAT {
		if err := s.nat.Enable(ctx); err != nil { return cleanup(err) }
	}
	if err := s.controller.ApplyInitial(ctx); err != nil { return cleanup(err) }
	prefixes := routePrefixes(effective)
	if err := s.routes.Apply(ctx, prefixes); err != nil { return cleanup(err) }
	s.started = true
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started { return nil }
	if err := s.routes.Apply(ctx, nil); err != nil {
		return fmt.Errorf("не удалось убрать маршруты перед остановкой туннеля: %w", err)
	}
	if err := s.process.Stop(ctx); err != nil { return err }
	s.started = false
	s.stopped = true
	return nil
}

func (s *Service) AddRoute(ctx context.Context, route protocol.Route) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.controller.Config()
	if err := s.controller.AddRoute(ctx, route); err != nil { return err }
	if !s.started { return nil }
	next := s.controller.Config()
	effective, err := next.EffectiveRoutes()
	if err == nil { err = s.routes.Apply(ctx, routePrefixes(effective)) }
	if err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rollbackErr := s.controller.ReplaceConfig(rollbackCtx, old)
		if rollbackErr != nil { return errors.Join(fmt.Errorf("не удалось применить системные маршруты: %w", err), fmt.Errorf("не удалось откатить UAPI: %w", rollbackErr)) }
		return err
	}
	return nil
}

func (s *Service) RemoveRoute(ctx context.Context, prefix netip.Prefix, peer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.controller.Config()
	if err := s.controller.RemoveRoute(ctx, prefix, peer); err != nil { return err }
	if !s.started { return nil }
	next := s.controller.Config()
	effective, err := next.EffectiveRoutes()
	if err == nil { err = s.routes.Apply(ctx, routePrefixes(effective)) }
	if err != nil {
		rollbackErr := s.controller.ReplaceConfig(context.Background(), old)
		if rollbackErr != nil { return errors.Join(fmt.Errorf("не удалось применить системные маршруты: %w", err), fmt.Errorf("не удалось откатить UAPI: %w", rollbackErr)) }
		return err
	}
	return nil
}

func (s *Service) Lookup(addr netip.Addr) (protocol.Route, bool) {
	return s.controller.Lookup(addr)
}

func (s *Service) Snapshot() []protocol.Route {
	return s.controller.Snapshot()
}

func routePrefixes(routes []protocol.Route) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes { out = append(out, route.Prefix) }
	return out
}

func hasIPv6(addresses []string, routes []protocol.Route) bool {
	for _, raw := range addresses {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && !prefix.Addr().Is4() { return true }
	}
	for _, route := range routes { if !route.Prefix.Addr().Is4() { return true } }
	return false
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

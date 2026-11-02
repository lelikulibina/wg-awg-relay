package control

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lelikulibina/wg-awg-relay/protocol"
)

type memoryRoutes struct {
	mu sync.Mutex
	routes []protocol.Route
}

func (m *memoryRoutes) AddRoute(_ context.Context, route protocol.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = append(m.routes, route)
	return nil
}
func (m *memoryRoutes) RemoveRoute(_ context.Context, prefix netip.Prefix, peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, route := range m.routes {
		if route.Prefix == prefix && route.Peer == peer {
			m.routes = append(m.routes[:i], m.routes[i+1:]...)
			return nil
		}
	}
	return nil
}
func (m *memoryRoutes) Snapshot() []protocol.Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]protocol.Route(nil), m.routes...)
}

func TestControlServerAndClient(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	service := &memoryRoutes{}
	server, err := NewServer(service, socket)
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func(){ done <- server.Serve(ctx) }()
	deadline := time.Now().Add(2*time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			conn, dialErr := net.DialTimeout("unix", socket, 50*time.Millisecond)
			if dialErr == nil { conn.Close(); break }
		}
		if time.Now().After(deadline) { cancel(); t.Fatal("управляющий сокет не появился") }
		time.Sleep(10*time.Millisecond)
	}
	client, err := NewClient(socket)
	if err != nil { t.Fatal(err) }
	route := protocol.Route{Prefix:netip.MustParsePrefix("10.0.0.0/8"), Peer:"uplink", Priority:4}
	if err := client.AddRoute(context.Background(), route); err != nil { t.Fatal(err) }
	routes, err := client.ListRoutes(context.Background())
	if err != nil { t.Fatal(err) }
	if len(routes) != 1 || routes[0].Peer != "uplink" { t.Fatalf("неверный список маршрутов: %#v", routes) }
	if err := client.RemoveRoute(context.Background(), route.Prefix, route.Peer); err != nil { t.Fatal(err) }
	routes, err = client.ListRoutes(context.Background())
	if err != nil { t.Fatal(err) }
	if len(routes) != 0 { t.Fatalf("маршрут не удалён: %#v", routes) }
	cancel()
	select {
	case err := <-done:
		if err != nil { t.Fatal(err) }
	case <-time.After(2*time.Second):
		t.Fatal("управляющий сервер не завершился после отмены контекста")
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) { t.Fatalf("Unix-сокет не удалён при остановке: %v", err) }
}

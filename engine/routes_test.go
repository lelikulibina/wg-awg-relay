package engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lelikulibina/wg-awg-relay/protocol"
)

func engineKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func fakeUAPI(t *testing.T, responses ...string) (protocol.UAPIClient, <-chan string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "awg.sock")
	listener, err := net.Listen("unix", path)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func(){ listener.Close() })
	requests := make(chan string, len(responses))
	go func() {
		defer close(requests)
		for _, response := range responses {
			conn, err := listener.Accept()
			if err != nil { return }
			var b strings.Builder
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil { conn.Close(); return }
				if line == "\n" || line == "\r\n" { break }
				b.WriteString(line)
			}
			requests <- b.String()
			_, _ = conn.Write([]byte(response + "\n\n"))
			conn.Close()
		}
	}()
	return protocol.UAPIClient{SocketPath:path}, requests
}

func TestRouteControllerAppliesInitialAndDynamicChanges(t *testing.T) {
	client, requests := fakeUAPI(t, "errno=0", "errno=0", "errno=0")
	cfg := protocol.Config{Peers: []protocol.Peer{{
		Name:"uplink", PublicKey:engineKey(),
		AllowedIPs:[]string{"0.0.0.0/0", "::/0"},
	}}}
	controller, err := NewRouteController(cfg, client)
	if err != nil { t.Fatal(err) }
	if err := controller.ApplyInitial(context.Background()); err != nil { t.Fatal(err) }
	initial := <-requests
	if !strings.Contains(initial, "replace_peers=true") { t.Fatalf("начальная конфигурация не заменила список пиров: %s", initial) }

	route := protocol.Route{Prefix:netip.MustParsePrefix("10.0.0.0/8"), Peer:"uplink", Priority:7}
	if err := controller.AddRoute(context.Background(), route); err != nil { t.Fatal(err) }
	add := <-requests
	if !strings.Contains(add, "replace_allowed_ips=true") || !strings.Contains(add, "allowed_ip=10.0.0.0/8") {
		t.Fatalf("динамическое добавление не применено точечно: %s", add)
	}
	if strings.Contains(add, "replace_peers=true") { t.Fatal("динамическое изменение не должно заменять все пиры") }
	got, ok := controller.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok || got.Prefix.String() != "10.0.0.0/8" { t.Fatalf("таблица не обновлена: %#v", got) }

	if err := controller.RemoveRoute(context.Background(), netip.MustParsePrefix("10.0.0.0/8"), "uplink"); err != nil { t.Fatal(err) }
	remove := <-requests
	if strings.Contains(remove, "allowed_ip=10.0.0.0/8") { t.Fatalf("удалённый маршрут остался в UAPI: %s", remove) }
	got, ok = controller.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok || got.Prefix.String() != "0.0.0.0/0" { t.Fatalf("после удаления должен сработать default route: %#v", got) }
	if controller.Applied() == false { t.Fatal("контроллер потерял состояние применённой конфигурации") }
}

func TestRouteControllerUpdatesModelBeforeInitialApply(t *testing.T) {
	client, requests := fakeUAPI(t, "errno=0")
	cfg := protocol.Config{Peers: []protocol.Peer{{Name:"uplink", PublicKey:engineKey()}}}
	controller, err := NewRouteController(cfg, client)
	if err != nil { t.Fatal(err) }
	if err := controller.AddRoute(context.Background(), protocol.Route{
		Prefix:netip.MustParsePrefix("192.0.2.0/24"), Peer:"uplink",
	}); err != nil { t.Fatal(err) }
	if _, ok := controller.Lookup(netip.MustParseAddr("192.0.2.1")); !ok { t.Fatal("маршрут не обновлён до запуска устройства") }
	if len(requests) != 0 { t.Fatal("UAPI не должен вызываться до ApplyInitial") }
	if err := controller.ApplyInitial(context.Background()); err != nil { t.Fatal(err) }
	request := <-requests
	if !strings.Contains(request, "allowed_ip=192.0.2.0/24") { t.Fatalf("начальная конфигурация не содержит предварительно добавленный маршрут: %s", request) }
}

func TestRouteControllerRollsBackFailedUpdate(t *testing.T) {
	client, requests := fakeUAPI(t, "errno=0", "errno=22", "errno=0")
	cfg := protocol.Config{Peers: []protocol.Peer{{Name:"uplink", PublicKey:engineKey(), AllowedIPs:[]string{"0.0.0.0/0"}}}}
	controller, err := NewRouteController(cfg, client)
	if err != nil { t.Fatal(err) }
	if err := controller.ApplyInitial(context.Background()); err != nil { t.Fatal(err) }
	_ = <-requests
	err = controller.AddRoute(context.Background(), protocol.Route{
		Prefix:netip.MustParsePrefix("198.51.100.0/24"), Peer:"uplink",
	})
	if err == nil { t.Fatal("ожидалась ошибка UAPI") }
	failedRequest := <-requests
	rollbackRequest := <-requests
	if !strings.Contains(failedRequest, "allowed_ip=198.51.100.0/24") { t.Fatalf("неверный запрос обновления: %s", failedRequest) }
	if strings.Contains(rollbackRequest, "allowed_ip=198.51.100.0/24") { t.Fatalf("откат не восстановил исходный AllowedIPs: %s", rollbackRequest) }
	got, ok := controller.Lookup(netip.MustParseAddr("198.51.100.7"))
	if !ok || got.Prefix.String() != "0.0.0.0/0" { t.Fatalf("локальная таблица не откатилась: %#v", got) }
}

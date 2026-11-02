package app

import (
	"context"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/lelikulibina/wg-awg-relay/protocol"
)

func appKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func TestServiceMaintainsRouteModelBeforeStart(t *testing.T) {
	cfg := protocol.Config{PrivateKey:appKey(), Peers: []protocol.Peer{{
		Name:"uplink", PublicKey:appKey(), AllowedIPs:[]string{"10.0.0.0/8"},
	}}}
	service, err := New(cfg, Options{BinaryPath:"amneziawg-go", InterfaceName:"awg0", SocketPath:"/tmp/awg0-test.sock"})
	if err != nil { t.Fatal(err) }
	if _, ok := service.Lookup(netip.MustParseAddr("10.1.1.1")); !ok { t.Fatal("исходный маршрут не попал в сервис") }
	if err := service.AddRoute(context.Background(), protocol.Route{
		Prefix:netip.MustParsePrefix("2001:db8::/32"), Peer:"uplink",
	}); err != nil { t.Fatal(err) }
	if _, ok := service.Lookup(netip.MustParseAddr("2001:db8::1")); !ok { t.Fatal("маршрут не добавлен до запуска процесса") }
}

func TestHasIPv6DetectsAddressesAndRoutes(t *testing.T) {
	if !hasIPv6([]string{"2001:db8::1/64"}, nil) { t.Fatal("IPv6 адрес интерфейса не распознан") }
	if !hasIPv6(nil, []protocol.Route{{Prefix:netip.MustParsePrefix("2001:db8::/32"), Peer:"uplink"}}) {
		t.Fatal("IPv6 маршрут не распознан")
	}
	if hasIPv6([]string{"10.0.0.1/24"}, []protocol.Route{{Prefix:netip.MustParsePrefix("10.0.0.0/8"), Peer:"uplink"}}) {
		t.Fatal("IPv4 ошибочно распознан как IPv6")
	}
}

package protocol

import (
	"strings"
	"testing"
)

func TestConfigCombinesPeerAndGlobalRoutes(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{
		"peers":[{"name":"edge","public_key":"test","routes":[{"prefix":"10.0.0.7/24"}]}],
		"routes":[{"prefix":"2001:db8::/32","priority":5}]
	}`))
	if err != nil { t.Fatal(err) }
	routes, err := cfg.Routes()
	if err != nil { t.Fatal(err) }
	if len(routes) != 2 { t.Fatalf("ожидалось два маршрута, получено %d", len(routes)) }
	if routes[0].Prefix.String() != "10.0.0.0/24" { t.Fatalf("префикс не нормализован: %s", routes[0].Prefix) }
	if routes[1].Peer != "edge" || routes[1].Prefix.String() != "2001:db8::/32" {
		t.Fatalf("неверно преобразован общий маршрут: %#v", routes[1])
	}
}

func TestGlobalRoutesRejectedWithMultiplePeers(t *testing.T) {
	cfg := Config{
		Peers: []Peer{{Name:"one"},{Name:"two"}},
		Routes: []RouteConfig{{Prefix:"0.0.0.0/0"}},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "ровно одного пира") {
		t.Fatalf("ожидалась понятная ошибка неоднозначного глобального маршрута, получено %v", err)
	}
}

func TestPeerRoutesSupportMultiplePeers(t *testing.T) {
	cfg := Config{Peers: []Peer{
		{Name:"one", Routes:[]RouteConfig{{Prefix:"10.0.0.0/8"}}},
		{Name:"two", Routes:[]RouteConfig{{Prefix:"2001:db8::/32"}}},
	}}
	routes, err := cfg.Routes()
	if err != nil { t.Fatal(err) }
	if len(routes) != 2 || routes[0].Peer != "one" || routes[1].Peer != "two" {
		t.Fatalf("неверное распределение маршрутов по пирам: %#v", routes)
	}
}

func TestDuplicatePeerNamesRejected(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"same"},{Name:"same"}}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка повторяющегося имени пира") }
}

func TestMalformedCIDRRejected(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"edge", Routes:[]RouteConfig{{Prefix:"10.0.0.1/99"}}}}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка некорректного CIDR") }
}

func TestGlobalRouteCanTargetNamedPeer(t *testing.T) {
	cfg := Config{
		Peers: []Peer{{Name: "first"}, {Name: "second"}},
		Routes: []RouteConfig{{Prefix: "172.16.0.0/12", Peer: "second"}},
	}
	routes, err := cfg.Routes()
	if err != nil { t.Fatal(err) }
	if len(routes) != 1 || routes[0].Peer != "second" {
		t.Fatalf("общий маршрут назначен неверному пиру: %#v", routes)
	}
}

func TestGlobalRouteRejectsUnknownPeer(t *testing.T) {
	cfg := Config{
		Peers: []Peer{{Name: "known"}},
		Routes: []RouteConfig{{Prefix: "172.16.0.0/12", Peer: "missing"}},
	}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка ссылки на неизвестный пир") }
}

func TestAmneziaWGParametersValidation(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name: "awg"}}, AmneziaWG: &AWGParameters{JC: 4, JMin: 80, JMax: 40}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка jmin > jmax") }
	cfg.AmneziaWG = &AWGParameters{S1: -1}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка отрицательного параметра AmneziaWG") }
}

func TestAmneziaWGHeaderRanges(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"edge"}}, AmneziaWG:&AWGParameters{H1:"10-20", H2:"42"}}
	if err := cfg.Validate(); err != nil { t.Fatalf("корректные диапазоны отклонены: %v", err) }
	cfg.AmneziaWG.H3 = "20-10"
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка перевёрнутого диапазона") }
	cfg.AmneziaWG.H3 = "4294967296"
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка переполнения uint32") }
}

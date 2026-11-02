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
	if err == nil || !strings.Contains(err.Error(), "укажите поле peer") {
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
	cfg := Config{Peers: []Peer{{Name:"edge"}}, AmneziaWG:&AWGParameters{H1:"10-20", H2:"42", HeaderProtectionKey:strings.Repeat("00", 32), S1:12, S2:12, S3:12, S4:12}}
	if err := cfg.Validate(); err != nil { t.Fatalf("корректные диапазоны отклонены: %v", err) }
	cfg.AmneziaWG.H3 = "20-10"
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка перевёрнутого диапазона") }
	cfg.AmneziaWG.H3 = "4294967296"
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка переполнения uint32") }
}

func TestAmneziaWGJunkRangeMustBeOrderedEvenWhenJMaxIsZero(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"edge"}}, AmneziaWG:&AWGParameters{JMin:1, JMax:0}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка jmin > jmax") }
}

func TestPeerEndpointRequiresNumericPort(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"edge", Endpoint:"vpn.example.com:abc"}}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка ненумерического порта") }
}

func TestEffectiveRoutesResolveEqualPrefixByPriority(t *testing.T) {
	cfg := Config{Peers: []Peer{
		{Name:"alpha", AllowedIPs:[]string{"10.0.0.0/8"}},
		{Name:"beta", AllowedIPs:[]string{"10.0.0.0/8"}},
	}, Routes: []RouteConfig{
		{Prefix:"10.0.0.0/8", Peer:"beta", Priority:20},
		{Prefix:"10.1.0.0/16", Peer:"alpha", Priority:1},
	}}
	routes, err := cfg.EffectiveRoutes()
	if err != nil { t.Fatal(err) }
	if len(routes) != 2 { t.Fatalf("ожидалось два эффективных префикса, получено %#v", routes) }
	if routes[0].Prefix.String() != "10.1.0.0/16" || routes[0].Peer != "alpha" {
		t.Fatalf("более специфичный маршрут потерян: %#v", routes[0])
	}
	if routes[1].Prefix.String() != "10.0.0.0/8" || routes[1].Peer != "beta" {
		t.Fatalf("равный префикс не разрешён по приоритету: %#v", routes[1])
	}
}

func TestPeerAllowedIPsReturnsCompleteEffectiveSet(t *testing.T) {
	cfg := Config{Peers: []Peer{
		{Name:"edge-a", AllowedIPs:[]string{"10.0.0.0/8", "2001:db8::/32"}},
		{Name:"edge-b"},
	}, Routes: []RouteConfig{{Prefix:"10.0.0.0/8", Peer:"edge-b", Priority:5}}}
	got, err := cfg.PeerAllowedIPs("edge-a")
	if err != nil { t.Fatal(err) }
	if len(got) != 1 || got[0].String() != "2001:db8::/32" {
		t.Fatalf("получен неполный/конфликтующий набор AllowedIPs: %#v", got)
	}
	if _, err := cfg.PeerAllowedIPs("missing"); err == nil { t.Fatal("ожидалась ошибка неизвестного пира") }
}

func TestAmneziaWGHeaderRangesCannotOverlap(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"edge"}}, AmneziaWG:&AWGParameters{H1:"100-200", H2:"200-300", HeaderProtectionKey:strings.Repeat("00", 32), S1:12, S2:12, S3:12, S4:12}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка пересекающихся диапазонов H1/H2") }
	cfg.AmneziaWG.H2 = "(off)"
	if err := cfg.Validate(); err != nil { t.Fatalf("отключённый диапазон не должен конфликтовать: %v", err) }
}

func TestAmneziaWGCustomPacketsCannotInjectUAPILines(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"edge"}}, AmneziaWG:&AWGParameters{I1:"<b 0x0102>" + string([]byte{10}) + "private_key=bad"}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка перевода строки в I1") }
}

func TestAmneziaWGHeaderRangesRequireProtectionKey(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"edge"}}, AmneziaWG:&AWGParameters{H1:"100-200"}}
	if err := cfg.Validate(); err == nil { t.Fatal("ожидалась ошибка отсутствующего HeaderProtectionKey") }
}

func TestParseConfigRejectsUnknownFields(t *testing.T) {
	_, err := ParseConfig([]byte(`{"peers":[],"listen_portt":51820}`))
	if err == nil { t.Fatal("ожидалась ошибка неизвестного поля") }
}

func TestParseConfigRejectsTrailingJSON(t *testing.T) {
	_, err := ParseConfig([]byte(`{"peers":[]} {"peers":[]}`))
	if err == nil { t.Fatal("ожидалась ошибка лишнего JSON-значения") }
}

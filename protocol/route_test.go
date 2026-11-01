package protocol

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, raw string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(raw)
	if err != nil { t.Fatal(err) }
	return p
}

func TestLookupUsesLongestPrefixBeforePriority(t *testing.T) {
	table := NewRouteTable()
	routes := []Route{
		{Prefix: mustPrefix(t, "10.0.0.0/8"), Peer: "broad", Priority: 1000},
		{Prefix: mustPrefix(t, "10.1.0.0/16"), Peer: "specific", Priority: -100},
	}
	if err := table.Replace(routes); err != nil { t.Fatal(err) }
	got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok || got.Peer != "specific" {
		t.Fatalf("ожидался наиболее длинный префикс, получено %#v, ok=%v", got, ok)
	}
}

func TestLookupPriorityOnlyForEqualPrefix(t *testing.T) {
	table := NewRouteTable()
	prefix := mustPrefix(t, "192.0.2.0/24")
	if err := table.Replace([]Route{
		{Prefix: prefix, Peer: "low", Priority: 1},
		{Prefix: prefix, Peer: "high", Priority: 9},
	}); err != nil { t.Fatal(err) }
	got, ok := table.Lookup(netip.MustParseAddr("192.0.2.44"))
	if !ok || got.Peer != "high" { t.Fatalf("ожидался пир high, получено %#v", got) }
}

func TestLookupIPv6(t *testing.T) {
	table := NewRouteTable()
	if err := table.Add(Route{Prefix: mustPrefix(t, "2001:db8:abcd::/48"), Peer: "v6"}); err != nil { t.Fatal(err) }
	got, ok := table.Lookup(netip.MustParseAddr("2001:db8:abcd:1::10"))
	if !ok || got.Peer != "v6" { t.Fatalf("не найден IPv6 маршрут: %#v", got) }
	if _, ok := table.Lookup(netip.MustParseAddr("2001:db8:abce::1")); ok { t.Fatal("найден маршрут вне префикса") }
}

func TestDynamicAddAndRemove(t *testing.T) {
	table := NewRouteTable()
	p := mustPrefix(t, "198.51.100.0/24")
	if err := table.Add(Route{Prefix:p, Peer:"uplink"}); err != nil { t.Fatal(err) }
	if _, ok := table.Lookup(netip.MustParseAddr("198.51.100.7")); !ok { t.Fatal("маршрут не появился после Add") }
	if !table.Remove(p, "uplink") { t.Fatal("Remove не сообщил об удалении") }
	if _, ok := table.Lookup(netip.MustParseAddr("198.51.100.7")); ok { t.Fatal("маршрут остался после Remove") }
}

func TestReplaceIsAtomicOnInvalidRoute(t *testing.T) {
	table := NewRouteTable()
	old := Route{Prefix:mustPrefix(t, "203.0.113.0/24"), Peer:"old"}
	if err := table.Add(old); err != nil { t.Fatal(err) }
	err := table.Replace([]Route{{Prefix:mustPrefix(t, "203.0.113.0/24"), Peer:"new"}, {Peer:"invalid"}})
	if err == nil { t.Fatal("ожидалась ошибка некорректного маршрута") }
	got, ok := table.Lookup(netip.MustParseAddr("203.0.113.9"))
	if !ok || got.Peer != "old" { t.Fatalf("таблица изменилась после неудачной замены: %#v", got) }
}

func TestEqualPriorityTieIsDeterministic(t *testing.T) {
	table := NewRouteTable()
	p := mustPrefix(t, "100.64.0.0/10")
	if err := table.Replace([]Route{{Prefix:p, Peer:"z"},{Prefix:p, Peer:"a"}}); err != nil { t.Fatal(err) }
	got, ok := table.Lookup(netip.MustParseAddr("100.64.1.1"))
	if !ok || got.Peer != "a" { t.Fatalf("ожидался стабильный выбор пира a, получено %#v", got) }
}

func FuzzLookupReturnsOnlyContainingPrefix(f *testing.F) {
	f.Add("10.0.0.0/8", "10.1.2.3")
	f.Add("2001:db8::/32", "2001:db8::1")
	f.Add("192.0.2.0/24", "198.51.100.1")
	f.Fuzz(func(t *testing.T, rawPrefix, rawAddr string) {
		prefix, err := netip.ParsePrefix(rawPrefix)
		if err != nil { t.Skip() }
		addr, err := netip.ParseAddr(rawAddr)
		if err != nil { t.Skip() }
		table := NewRouteTable()
		if err := table.Add(Route{Prefix: prefix, Peer: "fuzz"}); err != nil { t.Fatal(err) }
		got, ok := table.Lookup(addr)
		if ok && (!got.Prefix.Contains(addr) || got.Peer != "fuzz") {
			t.Fatalf("Lookup вернул маршрут, не содержащий адрес: %v для %v", got, addr)
		}
		if prefix.Addr().Is4() != addr.Is4() && ok {
			t.Fatalf("смешаны семейства адресов: %v для %v", got, addr)
		}
	})
}

func TestConcurrentRouteUpdatesAndLookups(t *testing.T) {
	table := NewRouteTable()
	prefix := mustPrefix(t, "10.20.0.0/16")
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(id int) {
			for j := 0; j < 200; j++ {
				_ = table.Add(Route{Prefix: prefix, Peer: "peer", Priority: id})
				table.Lookup(netip.MustParseAddr("10.20.1.1"))
				table.Snapshot()
				table.Remove(prefix, "peer")
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 4; i++ { <-done }
}

func TestLookupUnmapsIPv4MappedAddress(t *testing.T) {
	table := NewRouteTable()
	if err := table.Add(Route{Prefix:mustPrefix(t, "192.0.2.0/24"), Peer:"v4"}); err != nil { t.Fatal(err) }
	got, ok := table.Lookup(netip.MustParseAddr("::ffff:192.0.2.10"))
	if !ok || got.Peer != "v4" { t.Fatalf("IPv4-mapped адрес не сопоставлен IPv4 маршруту: %#v", got) }
}

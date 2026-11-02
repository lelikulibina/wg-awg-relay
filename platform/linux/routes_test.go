package linux

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type fakeRunner struct {
	commands [][]string
	failAt int
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	command := append([]string{name}, args...)
	f.commands = append(f.commands, command)
	if f.failAt > 0 && len(f.commands) == f.failAt {
		return []byte("simulated failure"), errors.New("command failed")
	}
	return nil, nil
}

func TestRouteManagerAddsIPv4AndIPv6(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewRouteManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	for _, raw := range []string{"10.20.0.0/16", "2001:db8:10::/48"} {
		if err := manager.Add(context.Background(), netip.MustParsePrefix(raw)); err != nil { t.Fatal(err) }
	}
	if len(runner.commands) != 2 { t.Fatalf("ожидалось две команды ip, получено %d", len(runner.commands)) }
	if strings.Join(runner.commands[0], " ") != "ip -4 route replace 10.20.0.0/16 dev awg0" {
		t.Fatalf("неверная IPv4-команда: %#v", runner.commands[0])
	}
	if strings.Join(runner.commands[1], " ") != "ip -6 route replace 2001:db8:10::/48 dev awg0" {
		t.Fatalf("неверная IPv6-команда: %#v", runner.commands[1])
	}
	if len(manager.Snapshot()) != 2 { t.Fatal("таблица платформенных маршрутов не обновилась") }
}

func TestRouteManagerApplyAddsBeforeRemoving(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewRouteManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	old := netip.MustParsePrefix("10.0.0.0/8")
	next := netip.MustParsePrefix("10.1.0.0/16")
	if err := manager.Add(context.Background(), old); err != nil { t.Fatal(err) }
	runner.commands = nil
	if err := manager.Apply(context.Background(), []netip.Prefix{next}); err != nil { t.Fatal(err) }
	if len(runner.commands) != 2 { t.Fatalf("ожидалось добавление и удаление, получено %#v", runner.commands) }
	if !strings.Contains(strings.Join(runner.commands[0], " "), "route replace 10.1.0.0/16") {
		t.Fatalf("новый маршрут должен устанавливаться первым: %#v", runner.commands)
	}
	if !strings.Contains(strings.Join(runner.commands[1], " "), "route del 10.0.0.0/8") {
		t.Fatalf("старый маршрут должен удаляться после нового: %#v", runner.commands)
	}
}

func TestRouteManagerRollsBackAddedRoutesOnFailure(t *testing.T) {
	runner := &fakeRunner{failAt:2}
	manager, err := NewRouteManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	err = manager.Apply(context.Background(), []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if err == nil { t.Fatal("ожидалась ошибка iproute2") }
	if len(manager.Snapshot()) != 0 { t.Fatal("локальный набор изменился после неудачной операции") }
	if len(runner.commands) != 3 { t.Fatalf("ожидались две попытки добавления и откат, команды: %#v", runner.commands) }
}

func TestRouteManagerRejectsInvalidInterface(t *testing.T) {
	if _, err := NewRouteManager("interface-name-is-too-long", &fakeRunner{}); err == nil {
		t.Fatal("ожидалась ошибка слишком длинного имени интерфейса")
	}
}

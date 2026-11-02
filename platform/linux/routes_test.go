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
	if len(runner.commands) != 4 { t.Fatalf("ожидались две policy rules и два маршрута, получено %d", len(runner.commands)) }
	if strings.Join(runner.commands[0], " ") != "ip -4 rule add priority 10000 not fwmark 51820 lookup 51820" {
		t.Fatalf("неверное IPv4 policy rule: %#v", runner.commands[0])
	}
	if strings.Join(runner.commands[1], " ") != "ip -6 rule add priority 10000 not fwmark 51820 lookup 51820" {
		t.Fatalf("неверное IPv6 policy rule: %#v", runner.commands[1])
	}
	if strings.Join(runner.commands[2], " ") != "ip -4 route replace 10.20.0.0/16 dev awg0 table 51820" {
		t.Fatalf("неверная IPv4-команда: %#v", runner.commands[2])
	}
	if strings.Join(runner.commands[3], " ") != "ip -6 route replace 2001:db8:10::/48 dev awg0 table 51820" {
		t.Fatalf("неверная IPv6-команда: %#v", runner.commands[3])
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
	if !strings.Contains(strings.Join(runner.commands[0], " "), "route replace 10.1.0.0/16 dev awg0 table 51820") {
		t.Fatalf("новый маршрут должен устанавливаться первым: %#v", runner.commands)
	}
	if !strings.Contains(strings.Join(runner.commands[1], " "), "route del 10.0.0.0/8 dev awg0 table 51820") {
		t.Fatalf("старый маршрут должен удаляться после нового: %#v", runner.commands)
	}
}

func TestRouteManagerRollsBackAddedRoutesOnFailure(t *testing.T) {
	runner := &fakeRunner{failAt:4}
	manager, err := NewRouteManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	err = manager.Apply(context.Background(), []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if err == nil { t.Fatal("ожидалась ошибка iproute2") }
	if len(manager.Snapshot()) != 0 { t.Fatal("локальный набор изменился после неудачной операции") }
	if len(runner.commands) != 7 { t.Fatalf("ожидались две policy rules, две попытки добавления, откат маршрута и удаление созданных правил, команды: %#v", runner.commands) }
}

func TestRouteManagerRejectsInvalidInterface(t *testing.T) {
	if _, err := NewRouteManager("interface-name-is-too-long", &fakeRunner{}); err == nil {
		t.Fatal("ожидалась ошибка слишком длинного имени интерфейса")
	}
}

type existingV4RuleRunner struct { calls [][]string }

func (r *existingV4RuleRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	joined := strings.Join(call, " ")
	if strings.Contains(joined, "ip -4 rule add") {
		return []byte("RTNETLINK answers: File exists"), errors.New("already exists")
	}
	return nil, nil
}

func TestRouteManagerDoesNotDeletePreexistingPolicyRule(t *testing.T) {
	runner := &existingV4RuleRunner{}
	manager, err := NewRouteManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	if err := manager.Add(context.Background(), prefix); err != nil { t.Fatal(err) }
	if err := manager.Remove(context.Background(), prefix); err != nil { t.Fatal(err) }
	for _, call := range runner.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "ip -4 rule del") { t.Fatal("менеджер удалил policy rule, который существовал до его запуска") }
	}
}

func TestRouteManagerTracksRoutesWhenRollbackFails(t *testing.T) {
	runner := &fakeRunner{failAt:5}
	manager, err := NewRouteManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	err = manager.Apply(context.Background(), []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if err == nil { t.Fatal("ожидалась ошибка основного применения и отката") }
	if len(manager.Snapshot()) != 1 { t.Fatalf("менеджер должен сохранить неопределённый маршрут для очистки: %#v", manager.Snapshot()) }
	runner.failAt = 0
	if err := manager.Apply(context.Background(), nil); err != nil { t.Fatal(err) }
	if len(manager.Snapshot()) != 0 { t.Fatal("повторная очистка не удалила маршрут") }
}

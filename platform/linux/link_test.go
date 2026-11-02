package linux

import (
	"context"
	"strings"
	"testing"
)

func TestLinkManagerConfiguresAddressesAndMTU(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewLinkManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	err = manager.Configure(context.Background(), []string{"10.66.0.1/24", "2001:db8::1/64"}, 1380)
	if err != nil { t.Fatal(err) }
	expected := []string{
		"ip link set dev awg0 mtu 1380",
		"ip -4 address replace 10.66.0.1/24 dev awg0",
		"ip -6 address replace 2001:db8::1/64 dev awg0",
		"ip link set dev awg0 up",
	}
	if len(runner.commands) != len(expected) { t.Fatalf("неверное число команд: %#v", runner.commands) }
	for i, want := range expected {
		if got := strings.Join(runner.commands[i], " "); got != want { t.Errorf("команда %d: ожидалось %q, получено %q", i, want, got) }
	}
}

func TestLinkManagerValidatesAllInputsBeforeExecuting(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewLinkManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	if err := manager.Configure(context.Background(), []string{"10.0.0.1/24", "bad-prefix"}, 1400); err == nil {
		t.Fatal("ожидалась ошибка адреса")
	}
	if len(runner.commands) != 0 { t.Fatal("команды не должны выполняться до проверки всех адресов") }
}

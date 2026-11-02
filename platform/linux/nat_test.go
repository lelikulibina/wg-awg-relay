package linux

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type nftRunner struct {
	calls [][]string
	table, chain, rule bool
}

func (r *nftRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	joined := strings.Join(call, " ")
	switch {
	case strings.Contains(joined, "list table"):
		if !r.table { return []byte("No such file or directory"), errors.New("not found") }
	case strings.Contains(joined, "add table"):
		r.table = true
	case strings.Contains(joined, "list chain") && strings.Contains(joined, "postrouting"):
		if !r.chain { return []byte("No such file or directory"), errors.New("not found") }
		if strings.Contains(joined, "-a") && r.rule { return []byte("oifname \"awg0\" masquerade # handle 1"), nil }
	case strings.Contains(joined, "add chain"):
		r.chain = true
	case strings.Contains(joined, "add rule"):
		r.rule = true
	}
	return nil, nil
}

func TestNATManagerEnableIsIdempotent(t *testing.T) {
	runner := &nftRunner{}
	manager, err := NewNATManager("awg0", runner)
	if err != nil { t.Fatal(err) }
	if err := manager.Enable(context.Background()); err != nil { t.Fatal(err) }
	if err := manager.Enable(context.Background()); err != nil { t.Fatal(err) }
	addRules := 0
	for _, call := range runner.calls { if strings.Contains(strings.Join(call, " "), "add rule") { addRules++ } }
	if addRules != 1 { t.Fatalf("masquerade должен добавляться один раз, добавлений: %d", addRules) }
	for _, call := range runner.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "conntrack") || strings.Contains(joined, "flush") {
			t.Fatalf("NAT-менеджер не должен очищать conntrack: %s", joined)
		}
	}
}

func TestForwardingManagerEnablesSelectedFamilies(t *testing.T) {
	runner := &fakeRunner{}
	manager := NewForwardingManager(runner)
	if err := manager.Enable(context.Background(), true); err != nil { t.Fatal(err) }
	if len(runner.commands) != 2 { t.Fatalf("ожидалось две команды sysctl: %#v", runner.commands) }
	if strings.Join(runner.commands[0], " ") != "sysctl -w net.ipv4.ip_forward=1" { t.Fatalf("неверная IPv4-команда: %#v", runner.commands[0]) }
	if strings.Join(runner.commands[1], " ") != "sysctl -w net.ipv6.conf.all.forwarding=1" { t.Fatalf("неверная IPv6-команда: %#v", runner.commands[1]) }
}

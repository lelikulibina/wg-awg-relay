package linux

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const relayNATTable = "wg_awg_relay"

// NATManager устанавливает отдельное правило masquerade в собственной nftables
// таблице. Он не очищает conntrack и не изменяет чужие таблицы/цепочки.
type NATManager struct {
	iface string
	runner Runner
	table string
}

func NewNATManager(iface string, runner Runner) (*NATManager, error) {
	if _, err := NewRouteManager(iface, runner); err != nil { return nil, err }
	if runner == nil { runner = ExecRunner{} }
	return &NATManager{iface:iface, runner:runner, table:relayNATTable}, nil
}

// Enable идемпотентно создаёт NAT-цепочку и masquerade для исходящего туннеля.
// Существующие conntrack-записи не затрагиваются.
func (m *NATManager) Enable(ctx context.Context) error {
	if _, err := m.runner.Run(ctx, "nft", "list", "table", "inet", m.table); err != nil {
		if out, addErr := m.runner.Run(ctx, "nft", "add", "table", "inet", m.table); addErr != nil {
			return fmt.Errorf("не удалось создать nftables-таблицу %s: %s: %w", m.table, strings.TrimSpace(string(out)), addErr)
		}
	}
	if _, err := m.runner.Run(ctx, "nft", "list", "chain", "inet", m.table, "postrouting"); err != nil {
		args := []string{"add", "chain", "inet", m.table, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"}
		if out, addErr := m.runner.Run(ctx, "nft", args...); addErr != nil {
			return fmt.Errorf("не удалось создать NAT-цепочку: %s: %w", strings.TrimSpace(string(out)), addErr)
		}
	}
	out, err := m.runner.Run(ctx, "nft", "-a", "list", "chain", "inet", m.table, "postrouting")
	if err != nil { return fmt.Errorf("не удалось прочитать NAT-цепочку: %s: %w", strings.TrimSpace(string(out)), err) }
	rule := fmt.Sprintf("oifname \"%s\" masquerade", m.iface)
	if strings.Contains(string(out), rule) { return nil }
	if out, err := m.runner.Run(ctx, "nft", "add", "rule", "inet", m.table, "postrouting", "oifname", m.iface, "masquerade"); err != nil {
		return fmt.Errorf("не удалось добавить masquerade: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ForwardingManager включает IP forwarding, не меняя другие sysctl-параметры.
type ForwardingManager struct {
	runner Runner
}

func NewForwardingManager(runner Runner) *ForwardingManager {
	if runner == nil { runner = ExecRunner{} }
	return &ForwardingManager{runner:runner}
}

func (m *ForwardingManager) Enable(ctx context.Context, ipv6 bool) error {
	if out, err := m.runner.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("не удалось включить IPv4 forwarding: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if ipv6 {
		if out, err := m.runner.Run(ctx, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
			return fmt.Errorf("не удалось включить IPv6 forwarding: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

var _ = errors.New

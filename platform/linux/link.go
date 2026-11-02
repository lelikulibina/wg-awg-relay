package linux

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// LinkManager configures addresses, MTU and administrative state of a TUN link.
type LinkManager struct {
	iface string
	runner Runner
}

func NewLinkManager(iface string, runner Runner) (*LinkManager, error) {
	if _, err := NewRouteManager(iface, runner); err != nil { return nil, err }
	if runner == nil { runner = ExecRunner{} }
	return &LinkManager{iface:iface, runner:runner}, nil
}

func (m *LinkManager) Configure(ctx context.Context, addresses []string, mtu int) error {
	if mtu < 0 || mtu > 65535 { return fmt.Errorf("MTU вне допустимого диапазона: %d", mtu) }
	for _, raw := range addresses {
		if _, err := netip.ParsePrefix(raw); err != nil { return fmt.Errorf("некорректный адрес интерфейса %q: %w", raw, err) }
	}
	if mtu > 0 {
		if out, err := m.runner.Run(ctx, "ip", "link", "set", "dev", m.iface, "mtu", strconv.Itoa(mtu)); err != nil {
			return fmt.Errorf("не удалось установить MTU: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	for _, raw := range addresses {
		prefix, _ := netip.ParsePrefix(raw)
		family := "-6"
		if prefix.Addr().Is4() { family = "-4" }
		if out, err := m.runner.Run(ctx, "ip", family, "address", "replace", prefix.String(), "dev", m.iface); err != nil {
			return fmt.Errorf("не удалось назначить адрес %s: %s: %w", prefix, strings.TrimSpace(string(out)), err)
		}
	}
	if out, err := m.runner.Run(ctx, "ip", "link", "set", "dev", m.iface, "up"); err != nil {
		return fmt.Errorf("не удалось поднять интерфейс %s: %s: %w", m.iface, strings.TrimSpace(string(out)), err)
	}
	return nil
}

var _ = errors.New

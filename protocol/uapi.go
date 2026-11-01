package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// keyToUAPI преобразует стандартный Base64 или hex ключ WireGuard в hex,
// который ожидает UAPI AmneziaWG/WireGuard.
func keyToUAPI(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" { return "", errors.New("ключ не задан") }
	var decoded []byte
	var err error
	if decoded, err = base64.StdEncoding.DecodeString(raw); err != nil {
		decoded, err = hex.DecodeString(raw)
	}
	if err != nil { return "", fmt.Errorf("ключ должен быть Base64 или hex: %w", err) }
	if len(decoded) != 32 { return "", fmt.Errorf("длина ключа должна быть 32 байта, получено %d", len(decoded)) }
	return hex.EncodeToString(decoded), nil
}

func appendUAPI(b *bytes.Buffer, key, value string) {
	if value != "" { fmt.Fprintf(b, "%s=%s\n", key, value) }
}

// BuildUAPIConfig создаёт полный запрос UAPI для настройки устройства.
// Адреса и MTU интерфейса настраиваются отдельно через сетевой адаптер.
func BuildUAPIConfig(cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil { return "", err }
	var b bytes.Buffer
	if cfg.PrivateKey != "" {
		key, err := keyToUAPI(cfg.PrivateKey)
		if err != nil { return "", fmt.Errorf("private_key: %w", err) }
		appendUAPI(&b, "private_key", key)
	}
	if cfg.ListenPort != 0 { appendUAPI(&b, "listen_port", strconv.Itoa(cfg.ListenPort)) }
	if awg := cfg.AmneziaWG; awg != nil {
		appendUAPI(&b, "jc", strconv.Itoa(awg.JC))
		appendUAPI(&b, "jmin", strconv.Itoa(awg.JMin))
		appendUAPI(&b, "jmax", strconv.Itoa(awg.JMax))
		appendUAPI(&b, "s1", strconv.Itoa(awg.S1))
		appendUAPI(&b, "s2", strconv.Itoa(awg.S2))
		appendUAPI(&b, "s3", strconv.Itoa(awg.S3))
		appendUAPI(&b, "s4", strconv.Itoa(awg.S4))
		appendUAPI(&b, "h1", awg.H1)
		appendUAPI(&b, "h2", awg.H2)
		appendUAPI(&b, "h3", awg.H3)
		appendUAPI(&b, "h4", awg.H4)
		appendUAPI(&b, "i1", awg.I1)
		appendUAPI(&b, "i2", awg.I2)
		appendUAPI(&b, "i3", awg.I3)
		appendUAPI(&b, "i4", awg.I4)
		appendUAPI(&b, "i5", awg.I5)
		appendUAPI(&b, "header_protection_key", awg.HeaderProtectionKey)
	}
	b.WriteString("replace_peers=true\n")
	routes, err := cfg.Routes()
	if err != nil { return "", err }
	byPeer := make(map[string][]string)
	for _, peer := range cfg.Peers {
		for _, raw := range peer.AllowedIPs {
			p, _ := netip.ParsePrefix(raw)
			byPeer[peer.Name] = append(byPeer[peer.Name], p.Masked().String())
		}
	}
	for _, route := range routes { byPeer[route.Peer] = append(byPeer[route.Peer], route.Prefix.String()) }

	peers := append([]Peer(nil), cfg.Peers...)
	sort.Slice(peers, func(i,j int) bool { return peers[i].Name < peers[j].Name })
	for _, peer := range peers {
		key, err := keyToUAPI(peer.PublicKey)
		if err != nil { return "", fmt.Errorf("пир %q: public_key: %w", peer.Name, err) }
		b.WriteString("public_key=" + key + "\n")
		if peer.Endpoint != "" {
			if _, _, err := net.SplitHostPort(peer.Endpoint); err != nil {
				return "", fmt.Errorf("пир %q: некорректный endpoint %q: %w", peer.Name, peer.Endpoint, err)
			}
			appendUAPI(&b, "endpoint", peer.Endpoint)
		}
		if peer.PersistentKeepalive != 0 {
			appendUAPI(&b, "persistent_keepalive_interval", strconv.Itoa(peer.PersistentKeepalive))
		}
		ips := uniqueSorted(byPeer[peer.Name])
		for _, ip := range ips { appendUAPI(&b, "allowed_ip", ip) }
	}
	return b.String(), nil
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values { set[value] = struct{}{} }
	out := make([]string, 0, len(set))
	for value := range set { out = append(out, value) }
	sort.Strings(out)
	return out
}

// ApplyUAPI отправляет запрос уже открытому UAPI-соединению и читает ответ
// до завершающей пустой строки. Соединение остаётся под управлением вызывающего кода.
func ApplyUAPI(ctx context.Context, conn net.Conn, request string) error {
	if conn == nil { return errors.New("UAPI-соединение не задано") }
	deadline, ok := ctx.Deadline()
	if ok {
		if err := conn.SetDeadline(deadline); err != nil { return err }
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := io.WriteString(conn, request+"\n"); err != nil { return fmt.Errorf("ошибка отправки UAPI-запроса: %w", err) }
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil { return fmt.Errorf("ошибка чтения ответа UAPI: %w", err) }
		line = strings.TrimRight(line, "\r\n")
		if line == "" { return nil }
		if strings.HasPrefix(line, "errno=") && line != "errno=0" {
			return fmt.Errorf("устройство отклонило UAPI-запрос: %s", line)
		}
	}
}

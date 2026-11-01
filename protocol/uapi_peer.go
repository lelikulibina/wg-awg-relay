package protocol

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// BuildPeerUAPI формирует запрос для обновления одного пира без замены
// остальных пиров устройства. allowedIPs — полный желаемый набор AllowedIPs
// этого пира (включая маршруты), поскольку replace_allowed_ips очищает старый.
func BuildPeerUAPI(peer Peer, allowedIPs []netip.Prefix) (string, error) {
	key, err := keyToUAPI(peer.PublicKey)
	if err != nil { return "", fmt.Errorf("пир %q: public_key: %w", peer.Name, err) }
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\n", key)
	if peer.Endpoint != "" {
		if _, _, err := net.SplitHostPort(peer.Endpoint); err != nil {
			return "", fmt.Errorf("пир %q: некорректный endpoint %q: %w", peer.Name, peer.Endpoint, err)
		}
		fmt.Fprintf(&b, "endpoint=%s\n", peer.Endpoint)
	}
	if peer.PersistentKeepalive != 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", strconv.Itoa(peer.PersistentKeepalive))
	}
	values := make([]string, 0, len(allowedIPs))
	for _, prefix := range allowedIPs {
		if !prefix.IsValid() { return "", errors.New("список AllowedIPs содержит некорректный префикс") }
		values = append(values, prefix.Masked().String())
	}
	for _, value := range uniqueSorted(values) { fmt.Fprintf(&b, "allowed_ip=%s\n", value) }
	return b.String(), nil
}

// BuildPeerRemovalUAPI формирует команду удаления пира по публичному ключу.
func BuildPeerRemovalUAPI(publicKey string) (string, error) {
	key, err := keyToUAPI(publicKey)
	if err != nil { return "", fmt.Errorf("public_key: %w", err) }
	return fmt.Sprintf("public_key=%s\nremove=true\n", key), nil
}

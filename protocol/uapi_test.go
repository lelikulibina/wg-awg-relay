package protocol

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func TestBuildUAPIConfigCombinesAllowedIPsAndRoutes(t *testing.T) {
	cfg := Config{
		PrivateKey: testKey(),
		ListenPort: 51820,
		FwMark: 51820,
		AmneziaWG: &AWGParameters{JC: 3, JMin: 50, JMax: 900, S1: 15, S2: 16, S3: 16, S4: 16, H1: "100-200", HeaderProtectionKey: testKey()},
		Peers: []Peer{{
			Name: "uplink", PublicKey: testKey(), Endpoint: "vpn.example.com:51820",
			AllowedIPs: []string{"10.0.0.1/24", "2001:db8::/32"},
			Routes: []RouteConfig{{Prefix: "10.10.0.0/16"}},
		}},
	}
	got, err := BuildUAPIConfig(cfg)
	if err != nil { t.Fatal(err) }
	for _, expected := range []string{
		"private_key=" + strings.Repeat("00", 32),
		"listen_port=51820", "fwmark=51820", "jc=3", "jmin=50", "jmax=900", "s1=15", "s2=16", "h1=100-200",
		"replace_peers=true", "endpoint=vpn.example.com:51820",
		"allowed_ip=10.0.0.0/24", "allowed_ip=10.10.0.0/16", "allowed_ip=2001:db8::/32",
	} {
		if !strings.Contains(got, expected) { t.Errorf("UAPI запрос не содержит %q:\n%s", expected, got) }
	}
}

func TestBuildUAPIRejectsInvalidKey(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"uplink", PublicKey:"not-a-key"}}}
	if _, err := BuildUAPIConfig(cfg); err == nil { t.Fatal("ожидалась ошибка ключа") }
}

func TestBuildUAPIRejectsInvalidEndpoint(t *testing.T) {
	cfg := Config{Peers: []Peer{{Name:"uplink", PublicKey:testKey(), Endpoint:"missing-port"}}}
	if _, err := BuildUAPIConfig(cfg); err == nil { t.Fatal("ожидалась ошибка endpoint") }
}

func TestApplyUAPI(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		buf := make([]byte, 128)
		for {
			n, err := server.Read(buf)
			if err != nil { return }
			if strings.Contains(string(buf[:n]), "\n\n") {
				_, _ = server.Write([]byte("errno=0\n\n"))
				return
			}
		}
	}()
	if err := ApplyUAPI(context.Background(), client, "listen_port=1234\n"); err != nil { t.Fatal(err) }
}

func TestApplyUAPIReportsDeviceError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		buf := make([]byte, 128)
		for {
			n, err := server.Read(buf)
			if err != nil { return }
			if strings.Contains(string(buf[:n]), "\n\n") {
				_, _ = server.Write([]byte("errno=22\n\n"))
				return
			}
		}
	}()
	if err := ApplyUAPI(context.Background(), client, "listen_port=1234\n"); err == nil {
		t.Fatal("ожидалась ошибка UAPI")
	}
}

func TestBuildPeerUAPIReplacesOnlySelectedPeersAllowedIPs(t *testing.T) {
	peer := Peer{Name: "edge", PublicKey: testKey(), Endpoint: "192.0.2.1:51820", PersistentKeepalive: 25}
	got, err := BuildPeerUAPI(peer, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if err != nil { t.Fatal(err) }
	for _, expected := range []string{"replace_allowed_ips=true", "persistent_keepalive_interval=25", "allowed_ip=10.0.0.0/24", "allowed_ip=2001:db8::/32"} {
		if !strings.Contains(got, expected) { t.Errorf("не найдено %q в %s", expected, got) }
	}
	if strings.Contains(got, "replace_peers=true") { t.Fatal("точечное обновление не должно заменять всех пиров") }
}

func TestBuildPeerRemovalUAPI(t *testing.T) {
	got, err := BuildPeerRemovalUAPI(testKey())
	if err != nil { t.Fatal(err) }
	if !strings.Contains(got, "remove=true") { t.Fatalf("нет команды удаления: %s", got) }
}

func TestBuildUAPIIncludesAWG31Settings(t *testing.T) {
	enabled, disabled := true, false
	cfg := Config{
		PrivateKey: testKey(),
		AmneziaWG: &AWGParameters{
			S1: 12, S2: 12, S3: 12, S4: 12,
			HeaderProtectionKey: testKey(),
			ContentPaddingAddition: "4-16",
			RekeyAfterTime: "30-60",
			RekeyTimeout: "(off)",
			RejectAfterTime: "120",
			KeepaliveTimeout: "10-20",
			MaxHandshakeAttempts: "5",
			RandomTrailers: &enabled,
			DisableCookies: &disabled,
		},
	}
	got, err := BuildUAPIConfig(cfg)
	if err != nil { t.Fatal(err) }
	for _, expected := range []string{
		"header_protection_key=" + strings.Repeat("00", 32),
		"content_padding_addition=4-16", "rekey_after_time=30-60",
		"rekey_timeout=(off)", "reject_after_time=120", "keepalive_timeout=10-20",
		"max_handshake_attempts=5", "random_trailers=1", "disable_cookies=0",
	} {
		if !strings.Contains(got, expected) { t.Errorf("не найдено %q в UAPI:\n%s", expected, got) }
	}
}

func TestApplyUAPICancelledContextInterruptsIO(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ApplyUAPI(ctx, client, "listen_port=1234\n") }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil { t.Fatal("ожидалась ошибка после отмены контекста") }
	case <-time.After(time.Second):
		t.Fatal("ApplyUAPI не прервал заблокированную операцию после отмены контекста")
	}
}

func TestUAPIClientApplyAndGetOverUnixSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "awg.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil { return }
			reader := bufio.NewReader(conn)
			first, _ := reader.ReadString('\n')
			if strings.TrimSpace(first) == "get=1" {
				_, _ = conn.Write([]byte("listen_port=51820\nerrno=0\n\n"))
			} else {
				_, _ = reader.ReadString('\n')
				_, _ = conn.Write([]byte("errno=0\n\n"))
			}
			conn.Close()
		}
	}()
	client := UAPIClient{SocketPath: socket}
	if err := client.Apply(context.Background(), "listen_port=51820\n"); err != nil { t.Fatal(err) }
	got, err := client.Get(context.Background())
	if err != nil { t.Fatal(err) }
	if !strings.Contains(got, "listen_port=51820") { t.Fatalf("неверный ответ UAPI get: %q", got) }
}

func TestKeyToUAPIAcceptsBase64AndHex(t *testing.T) {
	base64Key := testKey()
	hexKey := strings.Repeat("ab", 32)
	for _, raw := range []string{base64Key, hexKey} {
		got, err := keyToUAPI(raw)
		if err != nil { t.Fatalf("ключ %q отклонён: %v", raw, err) }
		if len(got) != 64 { t.Fatalf("ожидалось 64 hex-символа, получено %d", len(got)) }
	}
}

func TestBuildUAPIConfigSendsOnlyWinningPeerForEqualPrefix(t *testing.T) {
	keyA, keyB := strings.Repeat("00", 32), strings.Repeat("11", 32)
	cfg := Config{
		Peers: []Peer{
			{Name:"alpha", PublicKey:keyA, AllowedIPs:[]string{"10.0.0.0/8"}},
			{Name:"beta", PublicKey:keyB, AllowedIPs:[]string{"10.0.0.0/8"}},
		},
		Routes: []RouteConfig{{Prefix:"10.0.0.0/8", Peer:"beta", Priority:10}},
	}
	got, err := BuildUAPIConfig(cfg)
	if err != nil { t.Fatal(err) }
	sections := strings.Split(got, "public_key=")
	if len(sections) != 3 { t.Fatalf("ожидалось два блока пиров, получено %d: %s", len(sections)-1, got) }
	if strings.Contains(sections[1], "allowed_ip=10.0.0.0/8") {
		t.Fatal("конфликтующий AllowedIP остался назначен alpha")
	}
	if !strings.Contains(sections[2], "allowed_ip=10.0.0.0/8") {
		t.Fatal("победивший маршрут не назначен beta")
	}
}

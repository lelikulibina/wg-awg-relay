package protocol

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func testKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func TestBuildUAPIConfigCombinesAllowedIPsAndRoutes(t *testing.T) {
	cfg := Config{
		PrivateKey: testKey(),
		ListenPort: 51820,
		AmneziaWG: &AWGParameters{JC: 3, JMin: 50, JMax: 900, S1: 15, S2: 16, H1: "100-200"},
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
		"listen_port=51820", "jc=3", "jmin=50", "jmax=900", "s1=15", "s2=16", "h1=100-200",
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

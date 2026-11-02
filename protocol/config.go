package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// AWGParameters хранит параметры расширения AmneziaWG в форме конфигурации.
type AWGParameters struct {
	JC int `json:"jc,omitempty"`
	JMin int `json:"jmin,omitempty"`
	JMax int `json:"jmax,omitempty"`
	S1 int `json:"s1,omitempty"`
	S2 int `json:"s2,omitempty"`
	S3 int `json:"s3,omitempty"`
	S4 int `json:"s4,omitempty"`
	HeaderProtectionKey string `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
	RekeyAfterTime string `json:"rekey_after_time,omitempty"`
	RekeyTimeout string `json:"rekey_timeout,omitempty"`
	RejectAfterTime string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts string `json:"max_handshake_attempts,omitempty"`
	RandomTrailers *bool `json:"random_trailers,omitempty"`
	DisableCookies *bool `json:"disable_cookies,omitempty"`
	H1 string `json:"h1,omitempty"`
	H2 string `json:"h2,omitempty"`
	H3 string `json:"h3,omitempty"`
	H4 string `json:"h4,omitempty"`
	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`
}

// Peer описывает WireGuard-пир и принадлежащие ему сети назначения.
type Peer struct {
	Name string `json:"name"`
	PublicKey string `json:"public_key"`
	Endpoint string `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive int `json:"persistent_keepalive,omitempty"`
	Routes []RouteConfig `json:"routes,omitempty"`
}

// RouteConfig — сериализуемая форма маршрута.
type RouteConfig struct {
	Prefix string `json:"prefix"`
	Peer string `json:"peer,omitempty"`
	Priority int `json:"priority,omitempty"`
}

// Config объединяет настройки интерфейса, пиров и общие маршруты.
// Общие маршруты могут указывать поле peer. Если пир ровно один, его имя
// подставляется автоматически; при нескольких пирах поле peer обязательно.
type Config struct {
	PrivateKey string `json:"private_key,omitempty"`
	ListenPort int `json:"listen_port,omitempty"`
	FwMark uint32 `json:"fwmark,omitempty"`
	Address []string `json:"address,omitempty"`
	MTU int `json:"mtu,omitempty"`
	NAT bool `json:"nat,omitempty"`
	Peers []Peer `json:"peers"`
	Routes []RouteConfig `json:"routes,omitempty"`
	AmneziaWG *AWGParameters `json:"amneziawg,omitempty"`
}

// ParseConfig разбирает JSON и проверяет структуру конфигурации.
func ParseConfig(data []byte) (Config, error) {
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("не удалось разобрать конфигурацию: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil { return Config{}, errors.New("после конфигурации обнаружено лишнее JSON-значение") }
		return Config{}, fmt.Errorf("ошибка после конфигурации: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate проверяет уникальность пиров и корректность сетевых параметров.
func (c Config) Validate() error {
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("порт прослушивания вне диапазона: %d", c.ListenPort)
	}
	if c.MTU < 0 || c.MTU > 65535 { return fmt.Errorf("MTU вне допустимого диапазона: %d", c.MTU) }
	addresses := make(map[string]struct{}, len(c.Address))
	for i, raw := range c.Address {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil { return fmt.Errorf("address[%d]: некорректный префикс %q: %w", i, raw, err) }
		if _, exists := addresses[prefix.String()]; exists { return fmt.Errorf("адрес интерфейса %q указан повторно", prefix) }
		addresses[prefix.String()] = struct{}{}
	}
	if awg := c.AmneziaWG; awg != nil {
		if awg.JC < 0 || awg.JC > 65535 || awg.JMin < 0 || awg.JMin > 65535 || awg.JMax < 0 || awg.JMax > 65535 || awg.S1 < 0 || awg.S1 > 65535 || awg.S2 < 0 || awg.S2 > 65535 || awg.S3 < 0 || awg.S3 > 65535 || awg.S4 < 0 || awg.S4 > 65535 {
			return errors.New("числовые параметры AmneziaWG должны находиться в диапазоне uint16")
		}
		headerProtectionConfigured := awg.H1 != "" || awg.H2 != "" || awg.H3 != "" || awg.H4 != ""
		if headerProtectionConfigured && awg.HeaderProtectionKey == "" { return errors.New("для H1-H4 требуется HeaderProtectionKey") }
		if awg.HeaderProtectionKey != "" && (awg.S1 < 12 || awg.S2 < 12 || awg.S3 < 12 || awg.S4 < 12) { return errors.New("при HeaderProtectionKey значения S1-S4 должны быть не меньше 12") }
		if awg.JMin > awg.JMax {
			return errors.New("jmin не может превышать jmax")
		}
		headers := []struct{name, value string}{{"h1", awg.H1}, {"h2", awg.H2}, {"h3", awg.H3}, {"h4", awg.H4}}
		type headerRange struct { name string; low, high uint64; enabled bool }
		parsedHeaders := make([]headerRange, 0, len(headers))
		for _, header := range headers {
			low, high, enabled, err := parseUintRange(header.value, 32)
			if err != nil { return fmt.Errorf("%s: %w", header.name, err) }
			if enabled { parsedHeaders = append(parsedHeaders, headerRange{name:header.name, low:low, high:high, enabled:true}) }
		}
		for i := range parsedHeaders {
			for j := i + 1; j < len(parsedHeaders); j++ {
				a, b := parsedHeaders[i], parsedHeaders[j]
				if a.low <= b.high && b.low <= a.high {
					return fmt.Errorf("диапазоны %s и %s пересекаются", a.name, b.name)
				}
			}
		}
		for _, param := range []struct{name, value string}{{"content_padding_addition", awg.ContentPaddingAddition}, {"rekey_after_time", awg.RekeyAfterTime}, {"rekey_timeout", awg.RekeyTimeout}, {"reject_after_time", awg.RejectAfterTime}, {"keepalive_timeout", awg.KeepaliveTimeout}, {"max_handshake_attempts", awg.MaxHandshakeAttempts}} {
			if err := validateUintRange(param.value, 16); err != nil { return fmt.Errorf("%s: %w", param.name, err) }
		}
		for _, packet := range []struct{name, value string}{{"i1", awg.I1}, {"i2", awg.I2}, {"i3", awg.I3}, {"i4", awg.I4}, {"i5", awg.I5}} {
			if strings.ContainsAny(packet.value, "\r\n") { return fmt.Errorf("%s: значение не должно содержать перевод строки", packet.name) }
		}
	}
	peers := make(map[string]struct{}, len(c.Peers))
	for i, peer := range c.Peers {
		if strings.TrimSpace(peer.Name) == "" || peer.Name != strings.TrimSpace(peer.Name) {
			return fmt.Errorf("peers[%d]: не задано имя пира", i)
		}
		if _, exists := peers[peer.Name]; exists {
			return fmt.Errorf("повторяется имя пира %q", peer.Name)
		}
		peers[peer.Name] = struct{}{}
		if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
			return fmt.Errorf("пир %q: некорректный persistent keepalive", peer.Name)
		}
		if peer.Endpoint != "" {
			if err := validateEndpoint(peer.Endpoint); err != nil {
				return fmt.Errorf("пир %q: некорректный endpoint %q: %w", peer.Name, peer.Endpoint, err)
			}
		}

		for _, raw := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("пир %q: некорректная AllowedIP %q: %w", peer.Name, raw, err)
			}
		}
		for j, route := range peer.Routes {
			if route.Peer != "" && route.Peer != peer.Name {
				return fmt.Errorf("peers[%d].routes[%d]: маршрут вложенного пира не может ссылаться на %q", i, j, route.Peer)
			}
			if _, err := c.routeFromConfigForPeer(route, peer.Name); err != nil {
				return fmt.Errorf("peers[%d].routes[%d]: %w", i, j, err)
			}
		}
	}
	
	for i, route := range c.Routes {
		if _, err := c.routeFromConfig(route); err != nil {
			return fmt.Errorf("routes[%d]: %w", i, err)
		}
	}
	return nil
}


// EffectiveRoutes возвращает итоговые AllowedIPs для устройства. Явные маршруты
// объединяются с Peer.AllowedIPs. При совпадении префикса выбирается маршрут
// с большим приоритетом; при равенстве — лексикографически меньший пир.
// Разные длины префикса сохраняются, чтобы LPM работал в движке WireGuard.
func (c Config) EffectiveRoutes() ([]Route, error) {
	explicit, err := c.ConfiguredRoutes()
	if err != nil { return nil, err }
	winners := make(map[string]Route)
	add := func(candidate Route) {
		key := candidate.Prefix.String()
		current, exists := winners[key]
		if !exists || betterTie(candidate, current) { winners[key] = candidate }
	}
	for _, peer := range c.Peers {
		for _, raw := range peer.AllowedIPs {
			prefix, _ := netip.ParsePrefix(raw)
			normalized := prefix.Masked()
			add(Route{Prefix: normalized, Peer: peer.Name})
		}
	}
	for _, route := range explicit { add(route) }
	out := make([]Route, 0, len(winners))
	for _, route := range winners { out = append(out, route) }
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefix.Addr().Is4() != out[j].Prefix.Addr().Is4() { return out[i].Prefix.Addr().Is4() }
		if out[i].Prefix.Bits() != out[j].Prefix.Bits() { return out[i].Prefix.Bits() > out[j].Prefix.Bits() }
		return out[i].Prefix.String() < out[j].Prefix.String()
	})
	return out, nil
}

// PeerAllowedIPs возвращает полный эффективный набор AllowedIPs одного пира.
// Его следует передавать в BuildPeerUAPI при динамическом обновлении маршрутов.
func (c Config) PeerAllowedIPs(peerName string) ([]netip.Prefix, error) {
	found := false
	for _, peer := range c.Peers { if peer.Name == peerName { found = true; break } }
	if !found { return nil, fmt.Errorf("неизвестный пир %q", peerName) }
	routes, err := c.EffectiveRoutes()
	if err != nil { return nil, err }
	out := make([]netip.Prefix, 0)
	for _, route := range routes { if route.Peer == peerName { out = append(out, route.Prefix) } }
	return out, nil
}

// Routes объединяет глобальные маршруты и маршруты всех пиров в единую модель.
func (c Config) ConfiguredRoutes() ([]Route, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	out := make([]Route, 0, len(c.Routes))
	for _, peer := range c.Peers {
		for _, route := range peer.Routes {
			r, _ := c.routeFromConfigForPeer(route, peer.Name)
			out = append(out, r)
		}
	}
	for _, route := range c.Routes {
		r, _ := c.routeFromConfig(route)
		out = append(out, r)
	}
	return out, nil
}

func (c Config) routeFromConfigForPeer(cfg RouteConfig, peer string) (Route, error) {
	prefix, err := netip.ParsePrefix(cfg.Prefix)
	if err != nil {
		return Route{}, fmt.Errorf("некорректный префикс %q: %w", cfg.Prefix, err)
	}
	return (Route{Prefix: prefix, Peer: peer, Priority: cfg.Priority}).Normalize()
}

func (c Config) routeFromConfig(cfg RouteConfig) (Route, error) {
	prefix, err := netip.ParsePrefix(cfg.Prefix)
	if err != nil {
		return Route{}, fmt.Errorf("некорректный префикс %q: %w", cfg.Prefix, err)
	}
	peer := cfg.Peer
	if peer == "" {
		if len(c.Peers) != 1 {
			return Route{}, errors.New("для общего маршрута укажите поле peer; автоматическое назначение возможно только при одном пире")
		}
		peer = c.Peers[0].Name
	} else {
		found := false
		for _, candidate := range c.Peers {
			if candidate.Name == peer { found = true; break }
		}
		if !found { return Route{}, fmt.Errorf("общий маршрут ссылается на неизвестный пир %q", peer) }
	}
	return (Route{Prefix: prefix, Peer: peer, Priority: cfg.Priority}).Normalize()
}

func validateUintRange(raw string, bits int) error {
	_, _, _, err := parseUintRange(raw, bits)
	return err
}

func parseUintRange(raw string, bits int) (uint64, uint64, bool, error) {
	if raw == "" || raw == "(off)" { return 0, 0, false, nil }
	parts := strings.Split(raw, "-")
	if len(parts) > 2 || len(parts) == 2 && parts[0] == "" {
		return 0, 0, false, errors.New("ожидается число или диапазон x-y")
	}
	low, err := strconv.ParseUint(parts[0], 10, bits)
	if err != nil { return 0, 0, false, fmt.Errorf("некорректное числовое значение: %w", err) }
	high := low
	if len(parts) == 2 {
		high, err = strconv.ParseUint(parts[1], 10, bits)
		if err != nil { return 0, 0, false, fmt.Errorf("некорректная верхняя граница диапазона: %w", err) }
		if low > high { return 0, 0, false, errors.New("нижняя граница диапазона больше верхней") }
	}
	if low == 0 && high == 0 { return 0, 0, false, nil }
	return low, high, true, nil
}

func validateEndpoint(raw string) error {
	if strings.ContainsAny(raw, "\r\n\t ") || strings.Contains(raw, "=") {
		return errors.New("endpoint содержит недопустимые символы")
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil { return err }
	if host == "" { return errors.New("не задан адрес узла") }
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 { return errors.New("порт должен быть числом от 1 до 65535") }
	return nil
}

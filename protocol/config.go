package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// AWGParameters хранит параметры расширения AmneziaWG в форме конфигурации.
type AWGParameters struct {
	JC int `json:"jc,omitempty"`
	JMin int `json:"jmin,omitempty"`
	JMax int `json:"jmax,omitempty"`
	S1 int `json:"s1,omitempty"`
	S2 int `json:"s2,omitempty"`
	H1 int `json:"h1,omitempty"`
	H2 int `json:"h2,omitempty"`
	H3 int `json:"h3,omitempty"`
	H4 int `json:"h4,omitempty"`
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
	Peers []Peer `json:"peers"`
	Routes []RouteConfig `json:"routes,omitempty"`
}

// ParseConfig разбирает JSON и проверяет структуру конфигурации.
func ParseConfig(data []byte) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("не удалось разобрать конфигурацию: %w", err)
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
	if awg := c.AmneziaWG; awg != nil {
		if awg.JC < 0 || awg.JMin < 0 || awg.JMax < 0 || awg.S1 < 0 || awg.S2 < 0 ||
			awg.H1 < 0 || awg.H2 < 0 || awg.H3 < 0 || awg.H4 < 0 {
			return errors.New("параметры AmneziaWG не могут быть отрицательными")
		}
		if awg.JMax != 0 && awg.JMin > awg.JMax {
			return errors.New("jmin не может превышать jmax")
		}
	}
	peers := make(map[string]struct{}, len(c.Peers))
	for i, peer := range c.Peers {
		if strings.TrimSpace(peer.Name) == "" {
			return fmt.Errorf("peers[%d]: не задано имя пира", i)
		}
		if _, exists := peers[peer.Name]; exists {
			return fmt.Errorf("повторяется имя пира %q", peer.Name)
		}
		peers[peer.Name] = struct{}{}
		if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
			return fmt.Errorf("пир %q: некорректный persistent keepalive", peer.Name)
		}

		for _, raw := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("пир %q: некорректная AllowedIP %q: %w", peer.Name, raw, err)
			}
		}
		for j, route := range peer.Routes {
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

// Routes объединяет глобальные маршруты и маршруты всех пиров в единую модель.
func (c Config) Routes() ([]Route, error) {
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

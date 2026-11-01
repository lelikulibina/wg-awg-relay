package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// AWGParameters — дополнительные параметры обфускации AmneziaWG.
// Поля представлены строками, чтобы сохранить совместимость с форматом
// конфигурации AmneziaWG; интерпретация и применение параметров выполняются
// транспортным адаптером, а не таблицей маршрутов.
type AWGParameters struct {
	JC  int    `json:"jc,omitempty"`
	JMin int   `json:"jmin,omitempty"`
	JMax int   `json:"jmax,omitempty"`
	S1  int    `json:"s1,omitempty"`
	S2  int    `json:"s2,omitempty"`
	H1  string `json:"h1,omitempty"`
	H2  string `json:"h2,omitempty"`
	H3  string `json:"h3,omitempty"`
	H4  string `json:"h4,omitempty"`
	I1  string `json:"i1,omitempty"`
	I2  string `json:"i2,omitempty"`
	I3  string `json:"i3,omitempty"`
	I4  string `json:"i4,omitempty"`
	I5  string `json:"i5,omitempty"`
}

// Peer описывает WireGuard-пир и принадлежащие ему сети назначения.
type Peer struct {
	Name                string         `json:"name"`
	PublicKey           string         `json:"public_key"`
	Endpoint            string         `json:"endpoint,omitempty"`
	AllowedIPs          []string       `json:"allowed_ips,omitempty"`
	PersistentKeepalive int            `json:"persistent_keepalive,omitempty"`
	Routes              []RouteConfig  `json:"routes,omitempty"`
	AmneziaWG           *AWGParameters `json:"amneziawg,omitempty"`
}

// RouteConfig — сериализуемая форма маршрута.
type RouteConfig struct {
	Prefix   string `json:"prefix"`
	Priority int    `json:"priority,omitempty"`
}

// Config — единая конфигурация библиотеки. Общие маршруты и маршруты,
// вложенные в пиры, сводятся в один список при вызове Routes().
type Config struct {
	PrivateKey string        `json:"private_key,omitempty"`
	ListenPort int           `json:"listen_port,omitempty"`
	Peers      []Peer        `json:"peers"`
	Routes     []RouteConfig `json:"routes,omitempty"`
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
	}
	for i, route := range c.allRouteConfigs() {
		if _, err := c.routeFromConfig(route); err != nil {
			return fmt.Errorf("routes[%d]: %w", i, err)
		}
	}
	return nil
}

// Routes объединяет глобальные маршруты и маршруты всех пиров.
func (c Config) Routes() ([]Route, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	out := make([]Route, 0, len(c.Routes))
	for _, peer := range c.Peers {
		for _, route := range peer.Routes {
			r, err := c.routeFromConfigForPeer(route, peer.Name)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	for _, route := range c.Routes {
		r, err := c.routeFromConfig(route)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (c Config) allRouteConfigs() []RouteConfig {
	out := make([]RouteConfig, 0, len(c.Routes))
	for _, peer := range c.Peers {
		out = append(out, peer.Routes...)
	}
	return append(out, c.Routes...)
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
	// Глобальный маршрут допустим только при наличии ровно одного пира:
	// иначе адрес назначения не определяет, какому пиру принадлежит маршрут.
	if len(c.Peers) != 1 {
		return Route{}, errors.New("глобальный маршрут требует ровно одного пира; иначе задайте его в peers[].routes")
	}
	return (Route{Prefix: prefix, Peer: c.Peers[0].Name, Priority: cfg.Priority}).Normalize()
}

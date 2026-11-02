package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/lelikulibina/wg-awg-relay/protocol"
)

type Client struct {
	socket string
	http *http.Client
}

func NewClient(socketPath string) (*Client, error) {
	if strings.TrimSpace(socketPath) == "" { return nil, fmt.Errorf("не задан путь управляющего сокета") }
	dialer := &net.Dialer{Timeout:3*time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{socket:socketPath, http:&http.Client{Transport:transport, Timeout:10*time.Second}}, nil
}

func (c *Client) AddRoute(ctx context.Context, route protocol.Route) error {
	body := struct {
		Prefix string `json:"prefix"`
		Peer string `json:"peer"`
		Priority int `json:"priority,omitempty"`
	}{Prefix:route.Prefix.String(), Peer:route.Peer, Priority:route.Priority}
	return c.request(ctx, http.MethodPost, "/v1/routes", body, nil)
}

func (c *Client) RemoveRoute(ctx context.Context, prefix netip.Prefix, peer string) error {
	body := struct {
		Prefix string `json:"prefix"`
		Peer string `json:"peer"`
	}{Prefix:prefix.String(), Peer:peer}
	return c.request(ctx, http.MethodDelete, "/v1/routes", body, nil)
}

func (c *Client) ListRoutes(ctx context.Context) ([]protocol.Route, error) {
	var routes []protocol.Route
	if err := c.request(ctx, http.MethodGet, "/v1/routes", nil, &routes); err != nil { return nil, err }
	return routes, nil
}

func (c *Client) request(ctx context.Context, method, path string, body, result any) error {
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil { return err }
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, reader)
	if err != nil { return err }
	if body != nil { req.Header.Set("Content-Type", "application/json") }
	response, err := c.http.Do(req)
	if err != nil { return fmt.Errorf("не удалось обратиться к управляющему сокету %q: %w", c.socket, err) }
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var payload struct { Error string `json:"error"` }
		_ = json.NewDecoder(response.Body).Decode(&payload)
		if payload.Error == "" { payload.Error = response.Status }
		return fmt.Errorf("управляющий API: %s", payload.Error)
	}
	if result != nil {
		if err := json.NewDecoder(response.Body).Decode(result); err != nil { return fmt.Errorf("не удалось разобрать ответ управляющего API: %w", err) }
	}
	return nil
}

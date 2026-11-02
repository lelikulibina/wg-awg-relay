package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lelikulibina/wg-awg-relay/protocol"
)

type RouteService interface {
	AddRoute(context.Context, protocol.Route) error
	RemoveRoute(context.Context, netip.Prefix, string) error
	Snapshot() []protocol.Route
}

type Server struct {
	service RouteService
	socket string
}

func NewServer(service RouteService, socketPath string) (*Server, error) {
	if service == nil { return nil, errors.New("сервис маршрутов не задан") }
	if !filepath.IsAbs(socketPath) { return nil, errors.New("путь управляющего сокета должен быть абсолютным") }
	return &Server{service:service, socket:socketPath}, nil
}

// Serve publishes a local-only HTTP API over a Unix domain socket.
func (s *Server) Serve(ctx context.Context) error {
	if info, err := os.Lstat(s.socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 { return fmt.Errorf("путь %q существует и не является сокетом", s.socket) }
		if conn, dialErr := net.DialTimeout("unix", s.socket, 100*time.Millisecond); dialErr == nil {
			conn.Close()
			return fmt.Errorf("управляющий сокет %q уже используется", s.socket)
		}
		return fmt.Errorf("управляющий сокет %q существует, но недоступен; удалите устаревший файл вручную", s.socket)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("не удалось проверить управляющий сокет: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.socket), 0755); err != nil { return fmt.Errorf("не удалось создать каталог управляющего сокета: %w", err) }
	listener, err := net.Listen("unix", s.socket)
	if err != nil { return fmt.Errorf("не удалось открыть управляющий сокет: %w", err) }
	defer func(){ listener.Close(); _ = os.Remove(s.socket) }()
	if err := os.Chmod(s.socket, 0600); err != nil { return fmt.Errorf("не удалось ограничить права управляющего сокета: %w", err) }

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/routes", s.handleRoutes)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
		writeJSON(w, http.StatusOK, map[string]string{"status":"ok"})
	})
	server := &http.Server{Handler:mux, ReadHeaderTimeout:5*time.Second}
	serveErr := make(chan error, 1)
	go func(){ serveErr <- server.Serve(listener) }()
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) { return nil }
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil { _ = server.Close(); return err }
		err := <-serveErr
		if err != nil && !errors.Is(err, http.ErrServerClosed) { return err }
		return nil
	}
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.service.Snapshot())
	case http.MethodPost:
		var request struct {
			Prefix string `json:"prefix"`
			Peer string `json:"peer"`
			Priority int `json:"priority,omitempty"`
		}
		if err := decodeRequest(w, r, &request); err != nil { writeError(w, http.StatusBadRequest, err); return }
		prefix, err := netip.ParsePrefix(request.Prefix)
		if err != nil { writeError(w, http.StatusBadRequest, fmt.Errorf("некорректный prefix: %w", err)); return }
		if err := s.service.AddRoute(r.Context(), protocol.Route{Prefix:prefix, Peer:request.Peer, Priority:request.Priority}); err != nil {
			writeError(w, http.StatusBadRequest, err); return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status":"added"})
	case http.MethodDelete:
		var request struct {
			Prefix string `json:"prefix"`
			Peer string `json:"peer"`
		}
		if err := decodeRequest(w, r, &request); err != nil { writeError(w, http.StatusBadRequest, err); return }
		prefix, err := netip.ParsePrefix(request.Prefix)
		if err != nil { writeError(w, http.StatusBadRequest, fmt.Errorf("некорректный prefix: %w", err)); return }
		if err := s.service.RemoveRoute(r.Context(), prefix, request.Peer); err != nil {
			writeError(w, http.StatusBadRequest, err); return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status":"removed"})
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error":strings.TrimSpace(err.Error())})
}

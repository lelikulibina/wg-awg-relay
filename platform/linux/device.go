package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DeviceProcess запускает официальный userspace-движок AmneziaWG как отдельный
// процесс. Криптографию и обработку пакетов выполняет amneziawg-go.
type DeviceProcess struct {
	mu sync.Mutex
	binary string
	iface string
	socket string
	cmd *exec.Cmd
	done chan error
	stdout, stderr *os.File
}

func DefaultUAPISocketPath(iface string) string {
	return filepath.Join("/var/run/amneziawg", iface+".sock")
}

func NewDeviceProcess(binary, iface, socketPath string) (*DeviceProcess, error) {
	if strings.TrimSpace(binary) == "" { return nil, errors.New("не задан путь к amneziawg-go") }
	if _, err := NewRouteManager(iface, nil); err != nil { return nil, err }
	if socketPath == "" { socketPath = DefaultUAPISocketPath(iface) }
	if !filepath.IsAbs(socketPath) { return nil, errors.New("путь к UAPI-сокету должен быть абсолютным") }
	return &DeviceProcess{binary:binary, iface:iface, socket:socketPath}, nil
}

func (p *DeviceProcess) SetOutput(stdout, stderr *os.File) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stdout, p.stderr = stdout, stderr
}

// Start launches amneziawg-go in foreground mode and waits until its UAPI
// Unix socket accepts connections.
func (p *DeviceProcess) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.cmd != nil {
		select {
		case <-p.done:
			p.cmd, p.done = nil, nil
		default:
			p.mu.Unlock()
			return errors.New("AmneziaWG уже запущен")
		}
	}
	if conn, err := net.DialTimeout("unix", p.socket, 100*time.Millisecond); err == nil {
		conn.Close()
		p.mu.Unlock()
		return fmt.Errorf("UAPI-сокет %q уже занят работающим устройством", p.socket)
	}
	if info, err := os.Lstat(p.socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			p.mu.Unlock()
			return fmt.Errorf("путь %q существует и не является Unix-сокетом", p.socket)
		}
		p.mu.Unlock()
		return fmt.Errorf("UAPI-сокет %q существует, но недоступен; проверьте работающий процесс и удалите устаревший сокет вручную", p.socket)
	} else if !errors.Is(err, os.ErrNotExist) {
		p.mu.Unlock()
		return fmt.Errorf("не удалось проверить UAPI-сокет: %w", err)
	}
	cmd := exec.CommandContext(ctx, p.binary, "-f", p.iface)
	cmd.Stdout, cmd.Stderr = p.stdout, p.stderr
	if err := cmd.Start(); err != nil {
		p.mu.Unlock()
		return fmt.Errorf("не удалось запустить amneziawg-go: %w", err)
	}
	p.cmd = cmd
	p.done = make(chan error, 1)
	done := p.done
	go func() {
		done <- cmd.Wait()
		close(done)
	}()
	p.mu.Unlock()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		if conn, err := net.DialTimeout("unix", p.socket, 100*time.Millisecond); err == nil {
			conn.Close()
			return nil
		}
		select {
		case err := <-done:
			p.clear(cmd)
			if err == nil { return errors.New("amneziawg-go завершился до создания UAPI-сокета") }
			return fmt.Errorf("amneziawg-go завершился до готовности UAPI: %w", err)
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			p.clear(cmd)
			return ctx.Err()
		case <-timeout.C:
			_ = cmd.Process.Kill()
			<-done
			p.clear(cmd)
			return fmt.Errorf("UAPI-сокет %q не появился за 10 секунд", p.socket)
		case <-ticker.C:
		}
	}
}

// Stop asks the daemon to terminate gracefully. It force-kills the process only
// if the caller's deadline expires.
func (p *DeviceProcess) Stop(ctx context.Context) error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.mu.Unlock()
	if cmd == nil { return nil }
	if err := cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("не удалось отправить сигнал остановки AmneziaWG: %w", err)
	}
	select {
	case err := <-done:
		p.clear(cmd)
		if err != nil { return fmt.Errorf("AmneziaWG завершился с ошибкой: %w", err) }
		return nil
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		p.mu.Lock()
		p.cmd, p.done = nil, nil
		p.mu.Unlock()
		return ctx.Err()
	}
}

func (p *DeviceProcess) SocketPath() string { return p.socket }
func (p *DeviceProcess) Interface() string { return p.iface }

func (p *DeviceProcess) clear(cmd *exec.Cmd) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == cmd { p.cmd, p.done = nil, nil }
}

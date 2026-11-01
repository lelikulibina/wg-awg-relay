package protocol

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// UAPIClient открывает отдельное локальное IPC-соединение для каждой операции.
// Это соответствует модели AmneziaWG UAPI: одно соединение — одна команда.
type UAPIClient struct {
	SocketPath string
	Dialer net.Dialer
}

// Apply подключается к Unix-сокету работающего устройства и применяет запрос.
// Сам процесс amneziawg-go должен быть запущен заранее.
func (c UAPIClient) Apply(ctx context.Context, request string) error {
	if strings.TrimSpace(c.SocketPath) == "" { return errors.New("путь к UAPI-сокету не задан") }
	conn, err := c.Dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil { return fmt.Errorf("не удалось подключиться к UAPI-сокету %q: %w", c.SocketPath, err) }
	defer conn.Close()
	return ApplyUAPI(ctx, conn, request)
}

// Get получает текущее состояние устройства через UAPI-команду get=1.
func (c UAPIClient) Get(ctx context.Context) (string, error) {
	if strings.TrimSpace(c.SocketPath) == "" { return "", errors.New("путь к UAPI-сокету не задан") }
	conn, err := c.Dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil { return "", fmt.Errorf("не удалось подключиться к UAPI-сокету %q: %w", c.SocketPath, err) }
	defer conn.Close()
	if err := conn.SetDeadline(deadlineFromContext(ctx)); err != nil { return "", err }
	if _, err := conn.Write([]byte("get=1\n\n")); err != nil { return "", fmt.Errorf("ошибка отправки UAPI get: %w", err) }
	var b strings.Builder
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil { return "", fmt.Errorf("ошибка чтения UAPI get: %w", err) }
		if strings.TrimRight(line, "\r\n") == "" { break }
		b.WriteString(line)
	}
	return b.String(), nil
}

func deadlineFromContext(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok { return deadline }
	return time.Time{}
}

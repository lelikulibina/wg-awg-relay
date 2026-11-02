package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lelikulibina/wg-awg-relay/app"
	"github.com/lelikulibina/wg-awg-relay/control"
	"github.com/lelikulibina/wg-awg-relay/protocol"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "validate":
		err = validate(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	case "route":
		err = route(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("неизвестная команда %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Использование:")
	fmt.Fprintln(os.Stderr, "  wg-awg-relay validate -config config.json")
	fmt.Fprintln(os.Stderr, "  wg-awg-relay run -config config.json [-interface awg0] [-awg-binary amneziawg-go] [-uapi-socket path] [-control-socket path]")
	fmt.Fprintln(os.Stderr, "  wg-awg-relay route add -socket path -prefix CIDR -peer NAME [-priority N]")
	fmt.Fprintln(os.Stderr, "  wg-awg-relay route remove -socket path -prefix CIDR -peer NAME")
	fmt.Fprintln(os.Stderr, "  wg-awg-relay route list -socket path")
}

func loadConfig(path string) (protocol.Config, error) {
	if path == "" { return protocol.Config{}, errors.New("не задан путь к конфигурации (-config)") }
	data, err := os.ReadFile(path)
	if err != nil { return protocol.Config{}, fmt.Errorf("не удалось прочитать конфигурацию: %w", err) }
	return protocol.ParseConfig(data)
}

func validate(args []string) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	configPath := flags.String("config", "", "путь к JSON-конфигурации")
	if err := flags.Parse(args); err != nil { return err }
	cfg, err := loadConfig(*configPath)
	if err != nil { return err }
	routes, err := cfg.EffectiveRoutes()
	if err != nil { return err }
	fmt.Printf("Структура конфигурации корректна. Эффективных маршрутов: %d\n", len(routes))
	return nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := flags.String("config", "", "путь к JSON-конфигурации")
	iface := flags.String("interface", "awg0", "имя TUN-интерфейса")
	binary := flags.String("awg-binary", "amneziawg-go", "путь к исполняемому файлу amneziawg-go")
	socket := flags.String("uapi-socket", "", "путь к UAPI Unix-сокету")
	controlSocket := flags.String("control-socket", "/run/wg-awg-relay/control.sock", "путь управляющего Unix-сокета")
	if err := flags.Parse(args); err != nil { return err }
	cfg, err := loadConfig(*configPath)
	if err != nil { return err }
	service, err := app.New(cfg, app.Options{BinaryPath:*binary, InterfaceName:*iface, SocketPath:*socket})
	if err != nil { return err }

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if err := service.Start(runCtx); err != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		stopErr := service.Stop(stopCtx)
		return errors.Join(fmt.Errorf("не удалось запустить релей: %w", err), stopErr)
	}
	controlServer, err := control.NewServer(service, *controlSocket)
	if err != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = service.Stop(stopCtx)
		return err
	}
	controlErr := make(chan error, 1)
	go func(){ controlErr <- controlServer.Serve(runCtx) }()
	fmt.Fprintf(os.Stderr, "Релей запущен на интерфейсе %s. Управляющий сокет: %s. Для остановки нажмите Ctrl+C.\n", *iface, *controlSocket)
	var controlFailure error
	controlExited := false
	select {
	case <-ctx.Done():
	case err := <-controlErr:
		controlFailure = err
		controlExited = true
	}
	cancelRun()
	if !controlExited {
		select {
		case err := <-controlErr:
			if err != nil { controlFailure = err }
		case <-time.After(6*time.Second):
			controlFailure = errors.New("управляющий сервер не завершился вовремя")
		}
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	stopErr := service.Stop(stopCtx)
	if controlFailure != nil { return errors.Join(fmt.Errorf("управляющий сервер завершился: %w", controlFailure), stopErr) }
	if stopErr != nil { return fmt.Errorf("ошибка остановки релея: %w", stopErr) }
	return nil
}

func route(args []string) error {
	if len(args) == 0 { return errors.New("укажите действие route: add, remove или list") }
	action := args[0]
	flags := flag.NewFlagSet("route "+action, flag.ContinueOnError)
	socket := flags.String("socket", "/run/wg-awg-relay/control.sock", "путь управляющего Unix-сокета")
	prefixRaw := flags.String("prefix", "", "CIDR подсети")
	peer := flags.String("peer", "", "имя пира")
	priority := flags.Int("priority", 0, "приоритет при одинаковом префиксе")
	if err := flags.Parse(args[1:]); err != nil { return err }
	client, err := control.NewClient(*socket)
	if err != nil { return err }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch action {
	case "add":
		prefix, err := netip.ParsePrefix(*prefixRaw)
		if err != nil { return fmt.Errorf("некорректный prefix: %w", err) }
		if *peer == "" { return errors.New("не задано имя пира (-peer)") }
		return client.AddRoute(ctx, protocol.Route{Prefix:prefix, Peer:*peer, Priority:*priority})
	case "remove":
		prefix, err := netip.ParsePrefix(*prefixRaw)
		if err != nil { return fmt.Errorf("некорректный prefix: %w", err) }
		if *peer == "" { return errors.New("не задано имя пира (-peer)") }
		return client.RemoveRoute(ctx, prefix, *peer)
	case "list":
		routes, err := client.ListRoutes(ctx)
		if err != nil { return err }
		for _, route := range routes { fmt.Printf("%-40s %-20s %d\n", route.Prefix, route.Peer, route.Priority) }
		return nil
	default:
		return fmt.Errorf("неизвестное действие route %q", action)
	}
}

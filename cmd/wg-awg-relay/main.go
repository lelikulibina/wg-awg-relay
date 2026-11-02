package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lelikulibina/wg-awg-relay/app"
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
	fmt.Fprintln(os.Stderr, "  wg-awg-relay run -config config.json [-interface awg0] [-awg-binary amneziawg-go] [-uapi-socket path]")
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
	fmt.Printf("Конфигурация корректна. Эффективных маршрутов: %d\n", len(routes))
	return nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := flags.String("config", "", "путь к JSON-конфигурации")
	iface := flags.String("interface", "awg0", "имя TUN-интерфейса")
	binary := flags.String("awg-binary", "amneziawg-go", "путь к исполняемому файлу amneziawg-go")
	socket := flags.String("uapi-socket", "", "путь к UAPI Unix-сокету")
	if err := flags.Parse(args); err != nil { return err }
	cfg, err := loadConfig(*configPath)
	if err != nil { return err }
	service, err := app.New(cfg, app.Options{BinaryPath:*binary, InterfaceName:*iface, SocketPath:*socket})
	if err != nil { return err }

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := service.Start(ctx); err != nil { return fmt.Errorf("не удалось запустить релей: %w", err) }
	fmt.Fprintf(os.Stderr, "Релей запущен на интерфейсе %s. Для остановки нажмите Ctrl+C.\n", *iface)
	<-ctx.Done()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := service.Stop(stopCtx); err != nil { return fmt.Errorf("ошибка остановки релея: %w", err) }
	return nil
}

package linux

import (
	"path/filepath"
	"testing"
)

func TestDeviceProcessDefaultsToOfficialUAPISocket(t *testing.T) {
	process, err := NewDeviceProcess("/usr/bin/amneziawg-go", "awg0", "")
	if err != nil { t.Fatal(err) }
	expected := filepath.Join("/var/run/amneziawg", "awg0.sock")
	if process.SocketPath() != expected { t.Fatalf("ожидался сокет %q, получено %q", expected, process.SocketPath()) }
	if process.Interface() != "awg0" { t.Fatalf("неверное имя интерфейса: %q", process.Interface()) }
}

func TestDeviceProcessValidatesBinaryInterfaceAndSocket(t *testing.T) {
	if _, err := NewDeviceProcess("", "awg0", ""); err == nil { t.Fatal("ожидалась ошибка пустого пути к бинарному файлу") }
	if _, err := NewDeviceProcess("awg", "interface-name-is-too-long", ""); err == nil { t.Fatal("ожидалась ошибка имени интерфейса") }
	if _, err := NewDeviceProcess("awg", "awg0", "relative.sock"); err == nil { t.Fatal("ожидалась ошибка относительного пути сокета") }
}

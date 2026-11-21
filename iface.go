package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// wireguardRuntimeDir — каталог, в котором wireguard-go (и его форк из
// AmneziaWG) на macOS хранит управляющие сокеты и соответствие
// «имя конфига → реальный интерфейс».
const wireguardRuntimeDir = "/var/run/wireguard"

// realInterfaceFromNameFile возвращает реальное имя интерфейса (utunX)
// для имени конфига (mwgcorp) на macOS.
//
// wg-quick/awg-quick на Darwin создают интерфейс utunX, а в
// /var/run/wireguard/<имя>.name записывают его фактическое имя.
func realInterfaceFromNameFile(name string) string {
	if runtime.GOOS != "darwin" || name == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(wireguardRuntimeDir, name+".name"))
	if err != nil {
		return ""
	}
	real := strings.TrimSpace(string(data))
	if real == "" {
		return ""
	}
	// Убеждаемся, что интерфейс действительно поднят: существует сокет.
	if _, err := os.Stat(filepath.Join(wireguardRuntimeDir, real+".sock")); err != nil {
		return ""
	}
	return real
}

// resolveTunnelInterface возвращает имя, под которым туннель виден в системе,
// или пустую строку, если туннель не поднят.
func resolveTunnelInterface(t *Tunnel, live map[string]Kind) string {
	if t == nil {
		return ""
	}
	// macOS: сначала официальное соответствие из /var/run/wireguard.
	if real := realInterfaceFromNameFile(t.Interface); real != "" {
		if _, ok := live[real]; ok {
			return real
		}
	}
	// Ранее сохранённое реальное имя (например, после перезапуска приложения).
	if t.RealInterface != "" {
		if _, ok := live[t.RealInterface]; ok {
			return t.RealInterface
		}
	}
	// Linux/Windows: реальное имя совпадает с именем конфига.
	if _, ok := live[t.Interface]; ok {
		return t.Interface
	}
	return ""
}

// darwinWireGuardRuntimeInterfaces перечисляет реальные интерфейсы (utunX),
// известные wireguard-go/AmneziaWG по управляющим файлам в /var/run/wireguard.
// Используется как резервный источник, когда утилиты wg/awg недоступны.
func darwinWireGuardRuntimeInterfaces() []string {
	if runtime.GOOS != "darwin" {
		return nil
	}
	entries, err := os.ReadDir(wireguardRuntimeDir)
	if err != nil {
		return nil
	}
	var res []string
	seen := map[string]bool{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		res = append(res, name)
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".name"):
			if data, err := os.ReadFile(filepath.Join(wireguardRuntimeDir, name)); err == nil {
				add(string(data))
			}
		case strings.HasSuffix(name, ".sock"):
			add(strings.TrimSuffix(name, ".sock"))
		}
	}
	return res
}

// isUtunName сообщает, похоже ли имя на utun-интерфейс macOS.
func isUtunName(name string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "utun")
}

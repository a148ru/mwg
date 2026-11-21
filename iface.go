package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
//
// Порядок поиска:
//  1. /var/run/wireguard/<имя конфига>.name (macOS, точное соответствие);
//  2. сохранённое ранее реальное имя;
//  3. имя конфига (Linux/Windows);
//  4. сопоставление по IP-адресу из `Address =` конфига. Это важно, когда
//     туннель поднят не через копию mwg (например, вручную через wg-quick
//     с другим именем конфига) и файла .name для mwgcorp/mwginet нет.
func resolveTunnelInterface(t *Tunnel, live map[string]Kind) string {
	if t == nil {
		return ""
	}
	if real := realInterfaceFromNameFile(t.Interface); real != "" {
		if _, ok := live[real]; ok {
			return real
		}
		if interfaceExists(real) {
			return real
		}
	}
	if t.RealInterface != "" {
		if _, ok := live[t.RealInterface]; ok {
			return t.RealInterface
		}
		if interfaceExists(t.RealInterface) {
			return t.RealInterface
		}
	}
	if _, ok := live[t.Interface]; ok {
		return t.Interface
	}
	return matchInterfaceByAddress(t, live)
}

// interfaceExists проверяет наличие сетевого интерфейса в системе.
func interfaceExists(name string) bool {
	if name == "" {
		return false
	}
	_, err := net.InterfaceByName(name)
	return err == nil
}

// matchInterfaceByAddress находит интерфейс по IP-адресу из `Address =`.
// Сначала проверяются интерфейсы, уже известные как туннельные (live),
// затем остальные туннелеподобные интерфейсы системы.
func matchInterfaceByAddress(t *Tunnel, live map[string]Kind) string {
	if t == nil || t.ConfigPath == "" {
		return ""
	}
	cfg, err := parseWgConfig(t.ConfigPath)
	if err != nil {
		return ""
	}
	want := map[string]bool{}
	for _, a := range cfg.Addresses {
		ip := a
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		if n := normalizeIP(ip); n != "" {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return ""
	}

	addrs := systemInterfaceAddrs()

	seen := map[string]bool{}
	var candidates []string
	for name := range live {
		seen[name] = true
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)
	for _, name := range candidates {
		if matchesAnyAddr(addrs[name], want) {
			return name
		}
	}

	var others []string
	for name := range addrs {
		if seen[name] || !looksLikeTunnel(name) {
			continue
		}
		others = append(others, name)
	}
	sort.Strings(others)
	for _, name := range others {
		if matchesAnyAddr(addrs[name], want) {
			return name
		}
	}
	return ""
}

func matchesAnyAddr(have []string, want map[string]bool) bool {
	for _, h := range have {
		if want[h] {
			return true
		}
	}
	return false
}

// normalizeIP приводит адрес к каноническому виду (без маски и зоны).
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "[]")
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// systemInterfaceAddrs возвращает карту «интерфейс → IP-адреса».
func systemInterfaceAddrs() map[string][]string {
	switch runtime.GOOS {
	case "darwin":
		return darwinInterfaceAddrs()
	case "windows":
		return windowsInterfaceAddrs()
	default:
		return linuxInterfaceAddrs()
	}
}

func darwinInterfaceAddrs() map[string][]string {
	out, err := runCommand("ifconfig", "-a")
	if err != nil {
		return nil
	}
	res := map[string][]string{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			i := strings.IndexByte(line, ':')
			if i <= 0 {
				cur = ""
				continue
			}
			cur = line[:i]
			if _, ok := res[cur]; !ok {
				res[cur] = nil
			}
			continue
		}
		if cur == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || (f[0] != "inet" && f[0] != "inet6") {
			continue
		}
		ip := f[1]
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		if n := normalizeIP(ip); n != "" {
			res[cur] = append(res[cur], n)
		}
	}
	return res
}

func linuxInterfaceAddrs() map[string][]string {
	out, err := runCommand("ip", "-o", "addr", "show")
	if err != nil {
		return nil
	}
	res := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Пример: "2: eth0    inet 192.168.1.2/24 brd ..."
		if len(f) < 4 || (f[2] != "inet" && f[2] != "inet6") {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		ip := f[3]
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		if n := normalizeIP(ip); n != "" {
			res[name] = append(res[name], n)
		}
	}
	return res
}

type winIPAddr struct {
	InterfaceAlias string
	IPAddress      string
}

func windowsInterfaceAddrs() map[string][]string {
	const script = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress`
	out, err := runCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil || out == "" {
		return nil
	}
	var raw []winIPAddr
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		var one winIPAddr
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil
		}
		raw = []winIPAddr{one}
	}
	res := map[string][]string{}
	for _, r := range raw {
		if n := normalizeIP(r.IPAddress); n != "" {
			res[r.InterfaceAlias] = append(res[r.InterfaceAlias], n)
		}
	}
	return res
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

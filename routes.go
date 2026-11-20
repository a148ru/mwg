package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Route — запись таблицы маршрутизации.
type Route struct {
	Destination string
	Gateway     string
	Iface       string
	Metric      string
	Family      string // ipv4 / ipv6
}

var tunnelNameRe = regexp.MustCompile(`(?i)^(wg|awg|mwg)`)

// looksLikeTunnel определяет, относится ли имя интерфейса к wg/awg.
func looksLikeTunnel(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if strings.Contains(n, "wireguard") || strings.Contains(n, "amnezia") {
		return true
	}
	return tunnelNameRe.MatchString(n)
}

// liveInterfaces возвращает запущенные wg/awg интерфейсы.
// Сначала спрашиваем сами утилиты (wg/awg show interfaces), затем ОС.
func liveInterfaces() map[string]Kind {
	res := map[string]Kind{}

	for _, kind := range []Kind{KindWG, KindAWG} {
		ts := detectTools(kind)
		if ts.Show == "" {
			continue
		}
		if out, err := runCommand(ts.Show, "show", "interfaces"); err == nil {
			for _, name := range strings.Fields(out) {
				res[name] = kind
			}
		}
	}

	for _, name := range osTunnelInterfaces() {
		if _, ok := res[name]; ok {
			continue
		}
		if strings.HasPrefix(strings.ToLower(name), "awg") {
			res[name] = KindAWG
		} else {
			res[name] = KindWG
		}
	}
	return res
}

// osTunnelInterfaces — резервный способ перечисления туннельных интерфейсов.
func osTunnelInterfaces() []string {
	switch runtime.GOOS {
	case "windows":
		if names := windowsAdapterNames(); len(names) > 0 {
			return names
		}
		return windowsNetshInterfaces()
	case "darwin":
		return darwinInterfaces()
	default:
		return linuxInterfaces()
	}
}

func linuxInterfaces() []string {
	out, err := runCommand("ip", "-o", "link", "show")
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		// Пример: "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 ..."
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		if looksLikeTunnel(name) {
			names = append(names, name)
		}
	}
	return names
}

func darwinInterfaces() []string {
	out, err := runCommand("ifconfig", "-a")
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		name := line[:i]
		if looksLikeTunnel(name) {
			names = append(names, name)
		}
	}
	return names
}

type winAdapter struct {
	Name                 string
	InterfaceDescription string
}

func windowsAdapterNames() []string {
	const script = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-NetAdapter | Select-Object Name,InterfaceDescription | ConvertTo-Json -Compress`
	out, err := runCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil || out == "" {
		return nil
	}
	var adapters []winAdapter
	if err := json.Unmarshal([]byte(out), &adapters); err != nil {
		var one winAdapter
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil
		}
		adapters = []winAdapter{one}
	}
	var names []string
	for _, a := range adapters {
		if looksLikeTunnel(a.Name) || looksLikeTunnel(a.InterfaceDescription) {
			names = append(names, a.Name)
		}
	}
	return names
}

func windowsNetshInterfaces() []string {
	out, err := runCommand("netsh", "interface", "show", "interface")
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		// Колонки: Admin State | State | Type | Interface Name
		if len(line) < 48 {
			continue
		}
		name := strings.TrimSpace(line[47:])
		if looksLikeTunnel(name) {
			names = append(names, name)
		}
	}
	return names
}

// listRoutes читает системную таблицу маршрутизации.
func listRoutes() ([]Route, error) {
	switch runtime.GOOS {
	case "windows":
		return windowsRoutes()
	case "darwin":
		var res []Route
		var lastErr error
		for _, fam := range []struct{ netstat, family string }{
			{"inet", "ipv4"},
			{"inet6", "ipv6"},
		} {
			out, err := runCommand("netstat", "-rn", "-f", fam.netstat)
			if err != nil {
				lastErr = err
				continue
			}
			res = append(res, parseNetstatRoutes(out, fam.family)...)
		}
		if len(res) == 0 {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("таблица маршрутизации пуста")
		}
		return res, nil
	default:
		var res []Route
		out, err4 := runCommand("ip", "route", "show", "table", "all")
		if err4 == nil {
			res = append(res, parseIPRoutes(out, "ipv4")...)
		}
		// out6, err6 := runCommand("ip", "-6", "route", "show")
		out6, err6 := runCommand("ip", "-6", "route", "show", "table", "all")
		if err6 == nil {
			res = append(res, parseIPRoutes(out6, "ipv6")...)
		}
		if err4 != nil && err6 != nil {
			return nil, err4
		}
		return res, nil
	}
}

func parseIPRoutes(out, family string) []Route {
	var res []Route
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		r := Route{Destination: f[0], Family: family}
		for i := 1; i < len(f); i++ {
			switch f[i] {
			case "via":
				if i+1 < len(f) {
					r.Gateway = f[i+1]
					i++
				}
			case "dev":
				if i+1 < len(f) {
					r.Iface = f[i+1]
					i++
				}
			case "metric":
				if i+1 < len(f) {
					r.Metric = f[i+1]
					i++
				}
			}
		}
		res = append(res, r)
	}
	return res
}

func parseNetstatRoutes(out, family string) []Route {
	var res []Route
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Destination") ||
			strings.HasPrefix(trimmed, "Routing tables") ||
			strings.HasPrefix(trimmed, "Internet:") ||
			strings.HasPrefix(trimmed, "Internet6:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// Destination Gateway Flags Netif [Expire]
		res = append(res, Route{
			Destination: f[0],
			Gateway:     f[1],
			Iface:       f[3],
			Family:      family,
		})
	}
	return res
}

type winRoute struct {
	DestinationPrefix string
	NextHop           string
	InterfaceAlias    string
	RouteMetric       int
}

func windowsRoutes() ([]Route, error) {
	const script = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | ConvertTo-Json -Compress`
	out, err := runCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	var raw []winRoute
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		var one winRoute
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil, fmt.Errorf("не удалось разобрать вывод Get-NetRoute: %w", err)
		}
		raw = []winRoute{one}
	}
	res := make([]Route, 0, len(raw))
	for _, r := range raw {
		family := "ipv4"
		if strings.Contains(r.DestinationPrefix, ":") {
			family = "ipv6"
		}
		res = append(res, Route{
			Destination: r.DestinationPrefix,
			Gateway:     r.NextHop,
			Iface:       r.InterfaceAlias,
			Metric:      strconv.Itoa(r.RouteMetric),
			Family:      family,
		})
	}
	return res, nil
}

// tunnelRoutes возвращает только маршруты через wg/awg интерфейсы.
func tunnelRoutes(st *State) ([]Route, error) {
	all, err := listRoutes()
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for name := range liveInterfaces() {
		known[name] = true
	}
	for _, t := range st.ordered() {
		known[t.Interface] = true
	}

	var res []Route
	for _, r := range all {
		if r.Iface == "" {
			continue
		}
		if known[r.Iface] || looksLikeTunnel(r.Iface) {
			res = append(res, r)
		}
	}
	return res, nil
}

// isDefaultDest сообщает, является ли маршрут маршрутом по умолчанию.
func isDefaultDest(dest string) bool {
	switch strings.TrimSpace(dest) {
	case "default", "0.0.0.0/0", "::/0", "0/0":
		return true
	}
	return false
}

// defaultRouteInterfaces возвращает интерфейсы, через которые идёт default.
func defaultRouteInterfaces(routes []Route) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		if r.Iface == "" || !isDefaultDest(r.Destination) {
			continue
		}
		if !seen[r.Iface] {
			seen[r.Iface] = true
			out = append(out, r.Iface)
		}
	}
	return out
}

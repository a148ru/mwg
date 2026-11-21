package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// ---------- conf ----------

func cmdConf(args []string) int {
	fs := flag.NewFlagSet("conf", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "использование: mwg conf -c <corp.conf> | mwg conf -e <internet.conf>")
		fs.PrintDefaults()
	}
	corpPath := fs.String("c", "", "путь к конфигу корпоративного туннеля")
	inetPath := fs.String("e", "", "путь к конфигу интернет-туннеля (0.0.0.0/0)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	st, err := loadState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}

	if *corpPath == "" && *inetPath == "" {
		printStoredConfigs(st)
		return 0
	}

	if *corpPath != "" {
		if err := addConfig(st, RoleCorp, *corpPath); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка добавления корпоративного конфига: %v\n", err)
			return 1
		}
	}
	if *inetPath != "" {
		if err := addConfig(st, RoleInternet, *inetPath); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка добавления интернет-конфига: %v\n", err)
			return 1
		}
	}

	fmt.Println()
	printStoredConfigs(st)
	return 0
}

func addConfig(st *State, role Role, src string) error {
	abs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	cfg, err := parseWgConfig(abs)
	if err != nil {
		return err
	}

	ts := detectTools(cfg.Kind)
	if !ts.Usable() {
		return fmt.Errorf("для %s определён тип %s, но не найдены утилиты %s\nустановите: %s",
			abs, cfg.Kind, strings.Join(ts.Missing, ", "), installHint(cfg.Kind))
	}
	if len(ts.Missing) > 0 {
		fmt.Fprintf(os.Stderr, "предупреждение: не найдены утилиты %s\n", strings.Join(ts.Missing, ", "))
	}

	// Проверка default-маршрута: 0.0.0.0/0 разрешён только интернет-туннелю.
	if role == RoleCorp && cfg.HasDefault && !cfg.TableOff {
		return fmt.Errorf("конфиг %s содержит AllowedIPs 0.0.0.0/0: default-маршрут разрешён только интернет-туннелю (mwg conf -e <path>)", abs)
	}
	if role == RoleInternet && !cfg.HasDefault && !cfg.TableOff {
		fmt.Fprintln(os.Stderr, "предупреждение: в интернет-конфиге нет AllowedIPs 0.0.0.0/0 — default-маршрут через него не пойдёт")
	}
	if cfg.TableOff {
		fmt.Fprintln(os.Stderr, "примечание: Table = off — маршруты этим конфигом не добавляются")
	}
	if other := st.get(otherRole(role)); other != nil && other.HasDefault && cfg.HasDefault {
		return fmt.Errorf("default-маршрут 0.0.0.0/0 уже назначен туннелю %s (%s)", other.Interface, other.Role)
	}

	dir, err := stateDir()
	if err != nil {
		return err
	}
	iface := interfaceForRole(role)
	dst := filepath.Join(dir, iface+".conf")
	if err := os.WriteFile(dst, cfg.Raw, 0o600); err != nil {
		return fmt.Errorf("не удалось сохранить копию конфига: %w", err)
	}

	st.Tunnels[role] = &Tunnel{
		Role:       role,
		Kind:       cfg.Kind,
		Interface:  iface,
		ConfigPath: dst,
		SourcePath: abs,
		HasDefault: cfg.HasDefault,
		TableOff:   cfg.TableOff,
		AddedAt:    time.Now(),
	}
	if err := st.save(); err != nil {
		return err
	}

	fmt.Printf("добавлен %s-конфиг: %s → %s (%s, интерфейс %s)\n", role, abs, dst, cfg.Kind, iface)
	if real := resolveTunnelInterface(st.Tunnels[role], liveInterfaces()); real != "" {
		fmt.Printf("внимание: туннель уже запущен (%s), примените изменения: mwg down && mwg up\n", real)
	}
	return nil
}

func installHint(kind Kind) string {
	switch runtime.GOOS {
	case "darwin":
		if kind == KindAWG {
			return "brew install amneziawg-tools (или соберите awg-quick из репозитория AmneziaWG)"
		}
		return "brew install wireguard-tools"
	case "windows":
		if kind == KindAWG {
			return "установите AmneziaWG for Windows"
		}
		return "установите WireGuard for Windows"
	default:
		if kind == KindAWG {
			return "установите пакет amneziawg-tools"
		}
		return "установите пакет wireguard-tools"
	}
}

func printStoredConfigs(st *State) {
	if len(st.Tunnels) == 0 {
		fmt.Println("конфиги не добавлены. Используйте: mwg conf -c <corp.conf> и/или mwg conf -e <inet.conf>")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "РОЛЬ\tТИП\tИНТЕРФЕЙС\tDEFAULT\tИСХОДНЫЙ КОНФИГ\tКОПИЯ")
	for _, t := range st.ordered() {
		def := "нет"
		if t.HasDefault {
			def = "0.0.0.0/0"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", t.Role, t.Kind, t.Interface, def, t.SourcePath, t.ConfigPath)
	}
	w.Flush()
}

// ---------- up / down ----------

func cmdUp(args []string) int {
	st, err := loadState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	tunnels := st.ordered()
	if len(tunnels) == 0 {
		fmt.Fprintln(os.Stderr, "нет сохранённых конфигов; добавьте: mwg conf -c <corp.conf> и/или mwg conf -e <inet.conf>")
		return 1
	}
	if err := validateTunnels(tunnels); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "предупреждение: для запуска туннелей обычно нужны права root (sudo mwg up)")
	}

	live := liveInterfaces()
	failed := false

	// Порядок важен: сначала corp, затем internet (его default-маршрут главнее).
	for _, t := range tunnels {
		if real := resolveTunnelInterface(t, live); real != "" {
			fmt.Printf("%-8s %-8s уже запущен (%s)\n", t.Interface, t.Role, real)
			t.RealInterface = real
			continue
		}
		ts := detectTools(t.Kind)
		fmt.Printf("%-8s %-8s запуск (%s)...\n", t.Interface, t.Role, t.Kind)
		if err := tunnelUp(t, ts); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка запуска %s: %v\n", t.Interface, err)
			failed = true
			break
		}
	}

	// На macOS реальное имя интерфейса — utunX, поэтому определяем его
	// по /var/run/wireguard/<имя>.name, а не по имени конфига.
	live = waitForTunnels(tunnels, 5*time.Second)
	for _, t := range tunnels {
		real := resolveTunnelInterface(t, live)
		if real == "" {
			fmt.Fprintf(os.Stderr, "ошибка: интерфейс %s не появился\n", t.Interface)
			failed = true
			continue
		}
		t.RealInterface = real
	}
	if err := st.save(); err != nil {
		fmt.Fprintf(os.Stderr, "предупреждение: не удалось сохранить состояние: %v\n", err)
	}

	if !failed {
		// На macOS wg-quick/awg-quick применяют DNS только от последнего
		// поднятого туннеля, поэтому применяем DNS из обоих конфигов явно.
		if err := applyDNS(st, tunnels); err != nil {
			fmt.Fprintf(os.Stderr, "предупреждение: не удалось применить DNS: %v\n", err)
		}

		routes, err := tunnelRoutes(st)
		if err != nil {
			fmt.Fprintf(os.Stderr, "предупреждение: не удалось проверить маршруты: %v\n", err)
		} else {
			defs := defaultRouteInterfaces(routes)
			switch {
			case len(defs) > 1:
				fmt.Fprintf(os.Stderr, "ошибка: default-маршрут 0.0.0.0/0 активен на нескольких туннелях: %s\n", strings.Join(defs, ", "))
				failed = true
			case len(defs) == 1:
				fmt.Printf("default-маршрут: %s\n", defs[0])
			default:
				if inet := findRole(tunnels, RoleInternet); inet != nil && !inet.TableOff {
					fmt.Fprintln(os.Stderr, "предупреждение: default-маршрут 0.0.0.0/0 не найден ни на одном туннеле")
				}
			}
		}
	}

	if failed {
		return 1
	}
	fmt.Println("туннели запущены")
	return 0
}

func validateTunnels(tunnels []*Tunnel) error {
	var missing []string
	var defaults []string

	for _, t := range tunnels {
		cfg, err := parseWgConfig(t.ConfigPath)
		if err != nil {
			return fmt.Errorf("конфиг %s (%s): %w", t.Interface, t.Role, err)
		}
		t.Kind = cfg.Kind
		t.HasDefault = cfg.HasDefault
		t.TableOff = cfg.TableOff

		ts := detectTools(cfg.Kind)
		if !ts.Usable() {
			missing = append(missing, fmt.Sprintf("%s (%s): %s", t.Interface, cfg.Kind, strings.Join(ts.Missing, ", ")))
		} else if len(ts.Missing) > 0 {
			fmt.Fprintf(os.Stderr, "предупреждение: %s: не найдены утилиты %s (просмотр интерфейсов может быть ограничен)\n",
				cfg.Kind, strings.Join(ts.Missing, ", "))
		}

		if cfg.HasDefault && !cfg.TableOff {
			defaults = append(defaults, string(t.Role))
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("не найдены утилиты: %s\nустановите: %s / %s",
			strings.Join(missing, "; "), installHint(KindWG), installHint(KindAWG))
	}
	if len(defaults) > 1 {
		return fmt.Errorf("default-маршрут 0.0.0.0/0 задан в нескольких конфигах (%s); он разрешён только интернет-туннелю", strings.Join(defaults, ", "))
	}
	for _, t := range tunnels {
		if t.Role == RoleCorp && t.HasDefault && !t.TableOff {
			return fmt.Errorf("корпоративный конфиг %s содержит AllowedIPs 0.0.0.0/0; default-маршрут разрешён только интернет-туннелю", t.Interface)
		}
	}
	if inet := findRole(tunnels, RoleInternet); inet != nil && !inet.HasDefault && !inet.TableOff {
		fmt.Fprintln(os.Stderr, "предупреждение: интернет-конфиг не содержит AllowedIPs 0.0.0.0/0 — default-маршрут через него не пойдёт")
	}
	return nil
}

func findRole(tunnels []*Tunnel, role Role) *Tunnel {
	for _, t := range tunnels {
		if t.Role == role {
			return t
		}
	}
	return nil
}

func waitForTunnels(tunnels []*Tunnel, timeout time.Duration) map[string]Kind {
	deadline := time.Now().Add(timeout)
	for {
		live := liveInterfaces()
		all := true
		for _, t := range tunnels {
			if resolveTunnelInterface(t, live) == "" {
				all = false
				break
			}
		}
		if all || time.Now().After(deadline) {
			return live
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func cmdDown(args []string) int {
	st, err := loadState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	tunnels := st.ordered()
	if len(tunnels) == 0 {
		// Даже без сохранённых туннелей возвращаем DNS, если он остался
		// от предыдущего запуска (например, после сбоя).
		if err := restoreDNS(st); err != nil {
			fmt.Fprintf(os.Stderr, "предупреждение: не удалось восстановить DNS: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, "нет сохранённых конфигов")
		return 1
	}

	failed := false
	// Обратный порядок: сначала internet, затем corp.
	for i := len(tunnels) - 1; i >= 0; i-- {
		t := tunnels[i]
		real := resolveTunnelInterface(t, liveInterfaces())
		if real == "" {
			fmt.Printf("%-8s %-8s не запущен\n", t.Interface, t.Role)
			continue
		}
		ts := detectTools(t.Kind)
		if !ts.Usable() {
			fmt.Fprintf(os.Stderr, "ошибка: не найдена утилита остановки для %s (%s)\n", t.Interface, t.Kind)
			failed = true
			continue
		}
		fmt.Printf("%-8s %-8s остановка (%s)...\n", t.Interface, t.Role, real)
		if err := tunnelDown(t, ts); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка остановки %s: %v\n", t.Interface, err)
			failed = true
			continue
		}
		t.RealInterface = ""
		fmt.Printf("%-8s остановлен\n", t.Interface)
	}

	// Возвращаем исходные настройки DNS macOS.
	if err := restoreDNS(st); err != nil {
		fmt.Fprintf(os.Stderr, "предупреждение: не удалось восстановить DNS: %v\n", err)
	}
	if err := st.save(); err != nil {
		fmt.Fprintf(os.Stderr, "предупреждение: не удалось сохранить состояние: %v\n", err)
	}
	if failed {
		return 1
	}
	fmt.Println("туннели остановлены")
	return 0
}

// ---------- show ----------

func cmdShow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "использование: mwg show tun | mwg show route")
		return 2
	}
	switch args[0] {
	case "tun", "tunnels", "iface", "interfaces":
		return cmdShowTun()
	case "route", "routes":
		return cmdShowRoute()
	default:
		fmt.Fprintf(os.Stderr, "неизвестный раздел show %q (доступно: tun, route)\n", args[0])
		return 2
	}
}

func cmdShowTun() int {
	st, err := loadState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	live := liveInterfaces()

	type row struct{ role, iface, kind, state, conf string }
	var rows []row
	seen := map[string]bool{}

	for _, t := range st.ordered() {
		state := "down"
		iface := t.Interface
		if real := resolveTunnelInterface(t, live); real != "" {
			state = "up"
			iface = real
			seen[real] = true
		}
		rows = append(rows, row{t.Role.String(), iface, t.Kind.String(), state, t.ConfigPath})
		seen[t.Interface] = true
	}

	var extra []string
	for name := range live {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		rows = append(rows, row{"-", name, live[name].String(), "up", "-"})
	}

	if len(rows) == 0 {
		fmt.Println("интерфейсы wg/awg не найдены")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "РОЛЬ\tИНТЕРФЕЙС\tТИП\tСОСТОЯНИЕ\tКОНФИГ")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.role, r.iface, r.kind, r.state, r.conf)
	}
	w.Flush()
	return 0
}

func cmdShowRoute() int {
	st, err := loadState()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	routes, err := tunnelRoutes(st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка получения маршрутов:", err)
		return 1
	}
	if len(routes) == 0 {
		fmt.Println("маршрутов через wg/awg интерфейсы не найдено")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ИНТЕРФЕЙС\tСЕМЕЙСТВО\tНАЗНАЧЕНИЕ\tШЛЮЗ\tМЕТРИКА\tDEFAULT")
	for _, r := range routes {
		def := ""
		if isDefaultDest(r.Destination) {
			def = "да"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Iface, r.Family, r.Destination, dash(r.Gateway), dash(r.Metric), def)
	}
	w.Flush()

	defs := defaultRouteInterfaces(routes)
	switch {
	case len(defs) > 1:
		fmt.Fprintf(os.Stderr, "ошибка: default-маршрут 0.0.0.0/0 активен на нескольких туннелях: %s\n", strings.Join(defs, ", "))
		return 1
	case len(defs) == 1:
		fmt.Printf("default-маршрут: %s\n", defs[0])
	}
	return 0
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---------- check ----------

func cmdCheck(args []string) int {
	fmt.Printf("платформа: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if dir, err := stateDir(); err == nil {
		fmt.Printf("каталог состояния: %s\n", dir)
	}

	anyUsable := false
	for _, kind := range []Kind{KindWG, KindAWG} {
		ts := detectTools(kind)
		status := "OK"
		if !ts.Usable() {
			status = "не найдены: " + strings.Join(ts.Missing, ", ")
		} else if len(ts.Missing) > 0 {
			status = "частично, не найдены: " + strings.Join(ts.Missing, ", ")
			anyUsable = true
		} else {
			anyUsable = true
		}
		fmt.Printf("%-11s %s\n", kind, status)
		if ts.UpDown != "" {
			fmt.Printf("    up/down: %s\n", ts.UpDown)
		}
		if ts.Show != "" {
			fmt.Printf("    show:    %s\n", ts.Show)
		}
	}

	st, err := loadState()
	if err == nil {
		fmt.Println()
		printStoredConfigs(st)
	}

	if !anyUsable {
		fmt.Fprintln(os.Stderr, "не найдены ни wg, ни awg утилиты")
		return 1
	}
	return 0
}

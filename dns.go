package main

import (
	"net"
	"runtime"
	"strings"
)

// splitDNS разделяет значения DNS из конфига на DNS-серверы и домены поиска.
// В WireGuard/AmneziaWG в `DNS =` можно указывать и адреса, и домены.
func splitDNS(values []string) (servers, search []string) {
	seenServers := map[string]bool{}
	seenSearch := map[string]bool{}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if net.ParseIP(strings.Trim(v, "[]")) != nil {
			if !seenServers[v] {
				seenServers[v] = true
				servers = append(servers, v)
			}
			continue
		}
		if !seenSearch[v] {
			seenSearch[v] = true
			search = append(search, v)
		}
	}
	return servers, search
}

// collectDNS собирает DNS-серверы и домены поиска из всех конфигов.
// Порядок важен: сначала корпоративный туннель, затем интернет-туннель,
// чтобы корпоративные адреса имели приоритет.
func collectDNS(tunnels []*Tunnel) (servers, search []string) {
	seenServers := map[string]bool{}
	seenSearch := map[string]bool{}
	for _, t := range tunnels {
		cfg, err := parseWgConfig(t.ConfigPath)
		if err != nil {
			continue
		}
		s, d := splitDNS(cfg.DNS)
		for _, v := range s {
			if !seenServers[v] {
				seenServers[v] = true
				servers = append(servers, v)
			}
		}
		for _, v := range d {
			if !seenSearch[v] {
				seenSearch[v] = true
				search = append(search, v)
			}
		}
	}
	return servers, search
}

// applyDNS явно применяет DNS из конфигов туннелей.
//
// На macOS wg-quick/awg-quick применяют DNS через networksetup для всех
// сетевых служб. При двух туннелях второй `up` перезатирает DNS первого,
// а часть сборок awg-quick DNS вообще не настраивает. Поэтому после поднятия
// туннелей применяем объединённый DNS (corp + internet) самостоятельно.
func applyDNS(st *State, tunnels []*Tunnel) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	servers, search := collectDNS(tunnels)
	if len(servers) == 0 && len(search) == 0 {
		return nil
	}
	services := darwinNetworkServices()
	if len(services) == 0 {
		return nil
	}

	// Один раз сохраняем исходные настройки, чтобы восстановить их при `down`.
	if len(st.DNSBackup) == 0 {
		for _, svc := range services {
			st.DNSBackup = append(st.DNSBackup, dnsBackupEntry{
				Service:       svc,
				Servers:       darwinGetDNSServers(svc),
				SearchDomains: darwinGetSearchDomains(svc),
			})
		}
		if err := st.save(); err != nil {
			return err
		}
	}

	var lastErr error
	for _, svc := range services {
		if err := darwinSetDNS(svc, servers, search); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// restoreDNS возвращает DNS-настройки macOS, сохранённые перед `up`.
func restoreDNS(st *State) error {
	if runtime.GOOS != "darwin" || len(st.DNSBackup) == 0 {
		return nil
	}
	var lastErr error
	for _, b := range st.DNSBackup {
		if err := darwinSetDNS(b.Service, b.Servers, b.SearchDomains); err != nil {
			lastErr = err
		}
	}
	st.DNSBackup = nil
	if err := st.save(); err != nil && lastErr == nil {
		lastErr = err
	}
	return lastErr
}

// darwinNetworkServices возвращает список активных сетевых служб macOS.
func darwinNetworkServices() []string {
	out, err := runCommand("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var res []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Первая строка — пояснение про звёздочку.
		if strings.HasPrefix(line, "An asterisk") {
			continue
		}
		// Службы, отключённые в настройках, помечены звёздочкой.
		if strings.HasPrefix(line, "*") {
			continue
		}
		res = append(res, line)
	}
	return res
}

func darwinGetDNSServers(service string) []string {
	out, err := runCommand("networksetup", "-getdnsservers", service)
	if err != nil {
		return nil
	}
	return parseNetworkSetupList(out)
}

func darwinGetSearchDomains(service string) []string {
	out, err := runCommand("networksetup", "-getsearchdomains", service)
	if err != nil {
		return nil
	}
	return parseNetworkSetupList(out)
}

// parseNetworkSetupList разбирает вывод networksetup -getdnsservers/-getsearchdomains.
func parseNetworkSetupList(out string) []string {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "aren't any") || strings.Contains(lower, "not set") {
		return nil
	}
	var res []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			res = append(res, line)
		}
	}
	return res
}

// darwinSetDNS устанавливает DNS-серверы и домены поиска для сетевой службы.
// Пустой список очищает соответствующую настройку (значение Empty).
func darwinSetDNS(service string, servers, search []string) error {
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if len(servers) == 0 {
		_, err := runCommand("networksetup", "-setdnsservers", service, "Empty")
		record(err)
	} else {
		args := append([]string{"-setdnsservers", service}, servers...)
		_, err := runCommand("networksetup", args...)
		record(err)
	}

	if len(search) == 0 {
		_, err := runCommand("networksetup", "-setsearchdomains", service, "Empty")
		record(err)
	} else {
		args := append([]string{"-setsearchdomains", service}, search...)
		_, err := runCommand("networksetup", args...)
		record(err)
	}
	return firstErr
}

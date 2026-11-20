package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Kind — тип туннеля.
type Kind string

const (
	KindWG  Kind = "wireguard"
	KindAWG Kind = "amneziawg"
)

func (k Kind) String() string {
	if k == KindAWG {
		return "AmneziaWG"
	}
	return "WireGuard"
}

// Peer — секция [Peer] конфига.
type Peer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
}

// WgConfig — разобранный конфиг WireGuard/AmneziaWG.
type WgConfig struct {
	Path       string
	Kind       Kind
	Addresses  []string
	DNS        []string
	ListenPort string
	MTU        string
	Table      string
	TableOff   bool
	Peers      []Peer
	AllowedIPs []string
	HasDefault bool
	Raw        []byte
}

// Ключи [Interface], характерные для AmneziaWG.
var awgInterfaceKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"j1": true, "j2": true, "j3": true,
	"itime": true,
}

// parseWgConfig читает конфиг, определяет тип туннеля и наличие default-маршрута.
func parseWgConfig(path string) (*WgConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}

	cfg := &WgConfig{Path: path, Kind: KindWG, Raw: data}
	section := ""
	var cur *Peer

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				cfg.Peers = append(cfg.Peers, Peer{})
				cur = &cfg.Peers[len(cfg.Peers)-1]
			}
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		lkey := strings.ToLower(key)

		switch section {
		case "interface":
			if awgInterfaceKeys[lkey] {
				cfg.Kind = KindAWG
			}
			switch lkey {
			case "address":
				cfg.Addresses = append(cfg.Addresses, splitList(val)...)
			case "dns":
				cfg.DNS = append(cfg.DNS, splitList(val)...)
			case "listenport":
				cfg.ListenPort = val
			case "mtu":
				cfg.MTU = val
			case "table":
				cfg.Table = val
				if strings.EqualFold(val, "off") {
					cfg.TableOff = true
				}
			}
		case "peer":
			if cur == nil {
				continue
			}
			switch lkey {
			case "publickey":
				cur.PublicKey = val
			case "endpoint":
				cur.Endpoint = val
			case "allowedips":
				ips := splitList(val)
				cur.AllowedIPs = append(cur.AllowedIPs, ips...)
				cfg.AllowedIPs = append(cfg.AllowedIPs, ips...)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ошибка чтения %s: %w", path, err)
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("%s: не найдена секция [Peer] — это не похоже на конфиг WireGuard/AmneziaWG", path)
	}

	cfg.HasDefault = !cfg.TableOff && hasDefaultAllowedIPs(cfg.AllowedIPs)
	return cfg, nil
}

// hasDefaultAllowedIPs проверяет, забирает ли конфиг весь трафик:
// 0.0.0.0/0, ::/0 либо пара 0.0.0.0/1 + 128.0.0.0/1.
func hasDefaultAllowedIPs(list []string) bool {
	hasHalf0, hasHalf128 := false, false
	for _, raw := range list {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "0.0.0.0/0", "::/0":
			return true
		case "0.0.0.0/1":
			hasHalf0 = true
		case "128.0.0.0/1":
			hasHalf128 = true
		}
	}
	return hasHalf0 && hasHalf128
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

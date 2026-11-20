package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wgSample = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.10.0.2/32
DNS = 10.10.0.1

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = corp.example.com:51820
AllowedIPs = 10.10.0.0/24, 10.10.1.0/24
PersistentKeepalive = 25
`

const awgSample = `[Interface]
PrivateKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Address = 10.66.0.2/32
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890

[Peer]
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
Endpoint = inet.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
`

func writeTempConfig(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось записать конфиг: %v", err)
	}
	return p
}

func TestParseWireGuardConfig(t *testing.T) {
	cfg, err := parseWgConfig(writeTempConfig(t, "corp.conf", wgSample))
	if err != nil {
		t.Fatalf("parseWgConfig: %v", err)
	}
	if cfg.Kind != KindWG {
		t.Fatalf("тип = %s, ожидался %s", cfg.Kind, KindWG)
	}
	if cfg.HasDefault {
		t.Fatal("корпоративный конфиг не должен содержать default-маршрут")
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("peers = %d, ожидался 1", len(cfg.Peers))
	}
	if len(cfg.AllowedIPs) != 2 {
		t.Fatalf("allowed ips = %v, ожидалось 2 записи", cfg.AllowedIPs)
	}
	if cfg.TableOff {
		t.Fatal("Table = off не задан")
	}
}

func TestParseAmneziaConfig(t *testing.T) {
	cfg, err := parseWgConfig(writeTempConfig(t, "inet.conf", awgSample))
	if err != nil {
		t.Fatalf("parseWgConfig: %v", err)
	}
	if cfg.Kind != KindAWG {
		t.Fatalf("тип = %s, ожидался %s", cfg.Kind, KindAWG)
	}
	if !cfg.HasDefault {
		t.Fatal("ожидался default-маршрут (0.0.0.0/0)")
	}
}

func TestTableOffDisablesDefault(t *testing.T) {
	sample := strings.Replace(awgSample, "[Peer]", "Table = off\n\n[Peer]", 1)
	cfg, err := parseWgConfig(writeTempConfig(t, "inet.conf", sample))
	if err != nil {
		t.Fatalf("parseWgConfig: %v", err)
	}
	if !cfg.TableOff {
		t.Fatal("ожидался Table = off")
	}
	if cfg.HasDefault {
		t.Fatal("при Table = off default-маршрут не должен учитываться")
	}
}

func TestParseWithoutPeer(t *testing.T) {
	_, err := parseWgConfig(writeTempConfig(t, "broken.conf", "[Interface]\nPrivateKey = AAAA\n"))
	if err == nil {
		t.Fatal("ожидалась ошибка: нет секции [Peer]")
	}
}

func TestHasDefaultAllowedIPs(t *testing.T) {
	cases := []struct {
		ips  []string
		want bool
	}{
		{[]string{"0.0.0.0/0"}, true},
		{[]string{"::/0"}, true},
		{[]string{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{[]string{"0.0.0.0/1"}, false},
		{[]string{"10.0.0.0/8"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := hasDefaultAllowedIPs(c.ips); got != c.want {
			t.Errorf("hasDefaultAllowedIPs(%v) = %v, ожидалось %v", c.ips, got, c.want)
		}
	}
}

func TestIsDefaultDest(t *testing.T) {
	for _, dest := range []string{"default", "0.0.0.0/0", "::/0", "0/0"} {
		if !isDefaultDest(dest) {
			t.Errorf("%q должен считаться default", dest)
		}
	}
	for _, dest := range []string{"10.0.0.0/8", "0.0.0.0/1", ""} {
		if isDefaultDest(dest) {
			t.Errorf("%q не должен считаться default", dest)
		}
	}
}

func TestLooksLikeTunnel(t *testing.T) {
	yes := []string{"wg0", "awg0", "mwgcorp", "mwginet", "WireGuard Tunnel"}
	for _, n := range yes {
		if !looksLikeTunnel(n) {
			t.Errorf("%q должен распознаваться как туннель", n)
		}
	}
	no := []string{"Ethernet", "en0", "eth0", "Wi-Fi", ""}
	for _, n := range no {
		if looksLikeTunnel(n) {
			t.Errorf("%q не должен распознаваться как туннель", n)
		}
	}
}

func TestInterfaceNames(t *testing.T) {
	for _, role := range []Role{RoleCorp, RoleInternet} {
		name := interfaceForRole(role)
		if name == "" || len(name) > 15 {
			t.Errorf("имя интерфейса для %s = %q, ожидалось непустое и <= 15 символов", role, name)
		}
	}
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ToolSet — найденные утилиты для конкретного типа туннеля.
type ToolSet struct {
	Kind    Kind
	UpDown  string   // утилита поднятия/остановки (wg-quick / awg-quick / wireguard.exe)
	Show    string   // утилита просмотра (wg / awg)
	Missing []string // отсутствующие утилиты (для сообщений)
}

// Usable — можно ли запускать/останавливать туннели этим набором.
func (ts *ToolSet) Usable() bool { return ts.UpDown != "" }

// OK — доступны и управление, и просмотр.
func (ts *ToolSet) OK() bool { return ts.UpDown != "" && ts.Show != "" }

type toolSpec struct {
	UpDown []string
	Show   []string
}

func specFor(kind Kind) toolSpec {
	if runtime.GOOS == "windows" {
		if kind == KindAWG {
			return toolSpec{
				UpDown: []string{"amneziawg.exe", "awg-quick.exe"},
				Show:   []string{"awg.exe", "amneziawg.exe"},
			}
		}
		return toolSpec{
			UpDown: []string{"wireguard.exe"},
			Show:   []string{"wg.exe"},
		}
	}
	if kind == KindAWG {
		return toolSpec{UpDown: []string{"awg-quick"}, Show: []string{"awg"}}
	}
	return toolSpec{UpDown: []string{"wg-quick"}, Show: []string{"wg"}}
}

func detectTools(kind Kind) *ToolSet {
	spec := specFor(kind)
	ts := &ToolSet{Kind: kind}
	ts.UpDown = resolveFirst(spec.UpDown...)
	ts.Show = resolveFirst(spec.Show...)
	if ts.UpDown == "" {
		ts.Missing = append(ts.Missing, strings.Join(spec.UpDown, "/"))
	}
	if ts.Show == "" {
		ts.Missing = append(ts.Missing, strings.Join(spec.Show, "/"))
	}
	return ts
}

func resolveFirst(names ...string) string {
	for _, n := range names {
		if p := findBinary(n); p != "" {
			return p
		}
	}
	return ""
}

// findBinary ищет исполняемый файл в PATH и в стандартных каталогах установки.
func findBinary(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	for _, dir := range extraDirs() {
		p := filepath.Join(dir, name)
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(p), ".exe") {
			p += ".exe"
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func extraDirs() []string {
	switch runtime.GOOS {
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		dirs := []string{
			filepath.Join(pf, "WireGuard"),
			filepath.Join(pf, "AmneziaWG"),
			filepath.Join(pf, "AmneziaWG", "wireguard"),
			filepath.Join(pf, "AmneziaWG", "bin"),
		}
		if pf86 := os.Getenv("ProgramFiles(x86)"); pf86 != "" {
			dirs = append(dirs, filepath.Join(pf86, "WireGuard"))
		}
		return dirs
	case "darwin":
		return []string{"/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"}
	default:
		return []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	}
}

// runCommand выполняет команду и возвращает объединённый вывод.
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if s != "" {
			return s, fmt.Errorf("%s: %v: %s", filepath.Base(name), err, s)
		}
		return s, fmt.Errorf("%s: %v", filepath.Base(name), err)
	}
	return s, nil
}

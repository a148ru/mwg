package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// tunnelUp поднимает туннель.
//   Linux/macOS: wg-quick|awg-quick up <config>
//   Windows:     wireguard.exe|amneziawg.exe /installtunnelservice <config>
func tunnelUp(t *Tunnel, ts *ToolSet) error {
	if ts.UpDown == "" {
		return fmt.Errorf("не найдена утилита управления для %s", ts.Kind)
	}
	if runtime.GOOS == "windows" {
		out, err := runCommand(ts.UpDown, "/installtunnelservice", t.ConfigPath)
		if err != nil {
			if alreadyExists(out) {
				return nil
			}
			return err
		}
		return nil
	}
	out, err := runCommand(ts.UpDown, "up", t.ConfigPath)
	if err != nil {
		if alreadyExists(out) {
			return nil
		}
		return err
	}
	return nil
}

// tunnelDown останавливает туннель.
func tunnelDown(t *Tunnel, ts *ToolSet) error {
	if ts.UpDown == "" {
		return fmt.Errorf("не найдена утилита управления для %s", ts.Kind)
	}
	if runtime.GOOS == "windows" {
		out, err := runCommand(ts.UpDown, "/uninstalltunnelservice", t.Interface)
		if err != nil {
			if notInstalled(out) {
				return nil
			}
			return err
		}
		return nil
	}
	if _, err := os.Stat(t.ConfigPath); err == nil {
		out, err := runCommand(ts.UpDown, "down", t.ConfigPath)
		if err != nil {
			if notInstalled(out) {
				return nil
			}
			return err
		}
		return nil
	}
	out, err := runCommand(ts.UpDown, "down", t.Interface)
	if err != nil {
		if notInstalled(out) {
			return nil
		}
		return err
	}
	return nil
}

func alreadyExists(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "already") || strings.Contains(s, "уже")
}

func notInstalled(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "not a wireguard interface") ||
		strings.Contains(s, "is not installed") ||
		strings.Contains(s, "does not exist") ||
		strings.Contains(s, "no such") ||
		strings.Contains(s, "не установлен") ||
		strings.Contains(s, "не существует")
}

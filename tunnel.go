package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// tunnelUp поднимает туннель.
//
//	Linux/macOS: wg-quick|awg-quick up <config>
//	Windows:     wireguard.exe|amneziawg.exe /installtunnelservice <config>
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
//
// На macOS wg-quick/awg-quick определяют интерфейс по имени файла конфига,
// поэтому важно передать тот конфиг, с которым туннель был запущен. Сначала
// пробуем копию в каталоге состояния, затем исходный конфиг пользователя
// (туннель мог быть поднят вручную через `wg-quick up <исходный файл>`),
// и только потом имя интерфейса.
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

	var attempts []string
	if t.ConfigPath != "" {
		if _, err := os.Stat(t.ConfigPath); err == nil {
			attempts = append(attempts, t.ConfigPath)
		}
	}
	if t.SourcePath != "" && t.SourcePath != t.ConfigPath {
		if _, err := os.Stat(t.SourcePath); err == nil {
			attempts = append(attempts, t.SourcePath)
		}
	}
	if t.Interface != "" {
		attempts = append(attempts, t.Interface)
	}
	if len(attempts) == 0 {
		return fmt.Errorf("не найден конфиг для остановки туннеля %s", t.Interface)
	}

	var lastErr error
	for _, arg := range attempts {
		if _, err := runCommand(ts.UpDown, "down", arg); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Role — назначение туннеля.
type Role string

const (
	RoleCorp     Role = "corp"
	RoleInternet Role = "internet"
)

func (r Role) String() string { return string(r) }

func otherRole(r Role) Role {
	if r == RoleCorp {
		return RoleInternet
	}
	return RoleCorp
}

// Tunnel — сохранённый конфиг туннеля.
type Tunnel struct {
	Role      Role   `json:"role"`
	Kind      Kind   `json:"kind"`
	Interface string `json:"interface"` // имя из имени конфига (mwgcorp/mwginet)
	// RealInterface — фактическое имя интерфейса в системе. На macOS
	// wg-quick/awg-quick создают utunX, поэтому имя из конфига не совпадает
	// с реальным. Заполняется при успешном `up` и очищается при `down`.
	RealInterface string    `json:"real_interface,omitempty"`
	ConfigPath    string    `json:"config_path"` // копия конфига в каталоге состояния
	SourcePath    string    `json:"source_path"` // исходный путь, откуда добавлен конфиг
	HasDefault    bool      `json:"has_default_route"`
	TableOff      bool      `json:"table_off"`
	AddedAt       time.Time `json:"added_at"`
}

// dnsBackupEntry — исходные настройки DNS сетевой службы macOS,
// которые восстанавливаются при `mwg down`.
type dnsBackupEntry struct {
	Service       string   `json:"service"`
	Servers       []string `json:"servers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
}

// State — состояние приложения.
type State struct {
	Tunnels map[Role]*Tunnel `json:"tunnels"`
	// DNSBackup хранится только на macOS и только пока туннели подняты.
	DNSBackup []dnsBackupEntry `json:"dns_backup,omitempty"`
}

func newState() *State {
	return &State{Tunnels: map[Role]*Tunnel{}}
}

// stateDir возвращает каталог состояния (создаёт его при необходимости).
func stateDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("не удалось определить каталог конфигурации: %w", err)
	}
	dir := filepath.Join(base, "mwg")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("не удалось создать каталог %s: %w", dir, err)
	}
	return dir, nil
}

func stateFilePath() (string, error) {
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "state.json"), nil
}

// loadState читает состояние; отсутствие файла не является ошибкой.
func loadState() (*State, error) {
	path, err := stateFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}
	st := newState()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("файл состояния %s повреждён: %w", path, err)
	}
	if st.Tunnels == nil {
		st.Tunnels = map[Role]*Tunnel{}
	}
	return st, nil
}

// save атомарно записывает состояние.
func (s *State) save() error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *State) get(role Role) *Tunnel { return s.Tunnels[role] }

// ordered возвращает туннели в порядке запуска: сначала corp, затем internet.
func (s *State) ordered() []*Tunnel {
	var out []*Tunnel
	if t := s.get(RoleCorp); t != nil {
		out = append(out, t)
	}
	if t := s.get(RoleInternet); t != nil {
		out = append(out, t)
	}
	return out
}

// interfaceForRole задаёт имя сетевого интерфейса (<= 15 символов,
// чтобы подходить под ограничения wg-quick на Linux/macOS).
func interfaceForRole(role Role) string {
	switch role {
	case RoleCorp:
		return "mwgcorp"
	case RoleInternet:
		return "mwginet"
	default:
		return "mwg0"
	}
}

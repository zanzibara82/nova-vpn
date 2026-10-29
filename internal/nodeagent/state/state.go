// Package state хранит то, что узел не имеет права потерять между рестартами:
// приватный ключ и последний применённый набор вместе с узловым токеном.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	privateKeyFile = "node.key"
	stateFile      = "state.json"
)

type Store struct{ Dir string }

type Applied struct {
	ConfigVersion int64     `json:"config_version"`
	ETag          string    `json:"etag"`
	AppliedAt     time.Time `json:"applied_at"`
	Peers         int       `json:"peers"`
}

type NodeState struct {
	ServerID      string    `json:"server_id"`
	NodeToken     string    `json:"node_token"`
	TokenIssuedAt time.Time `json:"token_issued_at"`
	Applied       Applied   `json:"applied"`
}

// EnsureKey создаёт ключ при первом запуске и возвращает публичную половину.
// Повторный вызов не перевыпускает ключ: смена ключа требует правки сервера у
// администратора, поэтому «сгенерировать заново» — не восстановление, а поломка.
func (s *Store) EnsureKey() (string, bool, error) {
	if _, err := os.Stat(filepath.Join(s.Dir, privateKeyFile)); err == nil {
		key, err := s.PrivateKey()
		if err != nil {
			return "", false, err
		}
		return key.PublicKey().String(), false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("state: ключ: %w", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", false, fmt.Errorf("state: генерация ключа: %w", err)
	}
	if err := writeAtomic(filepath.Join(s.Dir, privateKeyFile), []byte(key.String())); err != nil {
		return "", false, err
	}
	return key.PublicKey().String(), true, nil
}

func (s *Store) PrivateKey() (wgtypes.Key, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, privateKeyFile))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("state: чтение ключа: %w", err)
	}
	key, err := wgtypes.ParseKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("state: разбор ключа: %w", err)
	}
	return key, nil
}

// Load возвращает пустое состояние, если файла ещё нет (узел не зарегистрирован),
// и ошибку, если файл испорчен. Второе важно: молча начать с нуля значило бы
// отправить узел в enroll без bootstrap-токена и оставить без доступа.
func (s *Store) Load() (NodeState, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return NodeState{}, nil
	}
	if err != nil {
		return NodeState{}, fmt.Errorf("state: чтение: %w", err)
	}
	var out NodeState
	if err := json.Unmarshal(raw, &out); err != nil {
		return NodeState{}, fmt.Errorf("state: файл состояния повреждён: %w", err)
	}
	return out, nil
}

func (s *Store) Save(ns NodeState) error {
	raw, err := json.Marshal(ns)
	if err != nil {
		return fmt.Errorf("state: сериализация: %w", err)
	}
	return writeAtomic(filepath.Join(s.Dir, stateFile), raw)
}

// writeAtomic пишет через временный файл в том же каталоге: rename в пределах
// одной файловой системы атомарен, поэтому читатель видит либо старую версию,
// либо новую, но не половину. Права ставятся до записи секрета.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state: каталог: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("state: права каталога: %w", err)
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("state: временный файл: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("state: права: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("state: запись: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("state: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("state: закрытие: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("state: переименование: %w", err)
	}
	return nil
}

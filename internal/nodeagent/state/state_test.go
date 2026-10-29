package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestEnsureKeyCreatesOnceAndKeepsMode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() == 0o700 {
		t.Fatal("исходный каталог уже 0700: проверка ужесточения не различает")
	}
	s := Store{Dir: dir}
	pub, created, err := s.EnsureKey()
	if err != nil || !created || pub == "" {
		t.Fatalf("первый вызов: ключ %q, создан %v, ошибка %v", pub, created, err)
	}
	pub2, created2, err := s.EnsureKey()
	if err != nil || created2 || pub2 != pub {
		t.Fatalf("повторный вызов: ключ %q, создан %v, ошибка %v", pub2, created2, err)
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("права ключа %o; ожидались 600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("права каталога %o; ожидались 700", got)
	}
}

func TestEnsureKeyDoesNotRegenerateBrokenKey(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	path := filepath.Join(dir, "node.key")
	if err := os.WriteFile(path, []byte("не-ключ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.EnsureKey(); err == nil {
		t.Fatal("испорченный ключ молча перевыпущен")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "не-ключ" {
		t.Fatal("файл ключа изменён при отказе")
	}
}

func TestEnsureKeyTightensExistingKeyMode(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.key")
	if err := os.WriteFile(path, []byte(key.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	pub, created, err := s.EnsureKey()
	if err != nil || created {
		t.Fatalf("существующий ключ: создан %v, ошибка %v", created, err)
	}
	if want := key.PublicKey().String(); pub != want {
		t.Fatal("публичный ключ не совпал с существующим")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("права ключа %o; ожидались 600", got)
	}
}

func TestEmptyDirRejected(t *testing.T) {
	s := Store{}
	if _, _, err := s.EnsureKey(); !errors.Is(err, errNoDir) {
		t.Fatalf("EnsureKey: ошибка %v", err)
	}
	if _, err := s.PrivateKey(); !errors.Is(err, errNoDir) {
		t.Fatalf("PrivateKey: ошибка %v", err)
	}
	if _, err := s.Load(); !errors.Is(err, errNoDir) {
		t.Fatalf("Load: ошибка %v", err)
	}
	if err := s.Save(NodeState{}); !errors.Is(err, errNoDir) {
		t.Fatalf("Save: ошибка %v", err)
	}
}

func TestSaveAndLoadRoundTripWithoutPrivateKey(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	if _, _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	want := NodeState{
		ServerID:      "8f0c0000-0000-4000-8000-000000000001",
		NodeToken:     "tok",
		TokenIssuedAt: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
		Applied: Applied{
			ConfigVersion: 7,
			ETag:          `"x"`,
			AppliedAt:     time.Date(2026, 10, 27, 11, 30, 0, 0, time.UTC),
			Peers:         2,
		},
	}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerID != want.ServerID {
		t.Fatalf("ServerID %q; ожидался %q", got.ServerID, want.ServerID)
	}
	if got.NodeToken != want.NodeToken {
		t.Fatal("узловой токен не совпал с сохранённым")
	}
	if got.Applied.ConfigVersion != want.Applied.ConfigVersion {
		t.Fatalf("версия конфигурации %d; ожидалась %d", got.Applied.ConfigVersion, want.Applied.ConfigVersion)
	}
	if got.Applied.ETag != want.Applied.ETag {
		t.Fatalf("ETag %q; ожидался %q", got.Applied.ETag, want.Applied.ETag)
	}
	if got.Applied.Peers != want.Applied.Peers {
		t.Fatalf("пиеров %d; ожидалось %d", got.Applied.Peers, want.Applied.Peers)
	}
	if !got.Applied.AppliedAt.Equal(want.Applied.AppliedAt) {
		t.Fatalf("время применения %v; ожидалось %v", got.Applied.AppliedAt, want.Applied.AppliedAt)
	}
	if !got.TokenIssuedAt.Equal(want.TokenIssuedAt) {
		t.Fatalf("время выдачи токена %v; ожидалось %v", got.TokenIssuedAt, want.TokenIssuedAt)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("права состояния %o; ожидались 600", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), key.String()) {
		t.Fatal("приватный ключ попал в state.json")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("временные файлы остались: %v", leftovers)
	}
}

func TestLoadMissingReturnsEmptyAndBrokenReturnsError(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	got, err := s.Load()
	if err != nil || got.ServerID != "" {
		t.Fatalf("отсутствующий файл: %+v %v", got, err)
	}
	if _, _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("испорченное состояние принято: узел молча потерял бы токен")
	}
}

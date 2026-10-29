package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureKeyCreatesOnceAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	pub, created, err := s.EnsureKey()
	if err != nil || !created || pub == "" {
		t.Fatalf("первый вызов: ключ %q, создан %v, ошибка %v", pub, created, err)
	}
	pub2, created2, err := s.EnsureKey()
	if err != nil || created2 || pub2 != pub {
		t.Fatalf("повторный вызов: ключ %q, создан %v, ошибка %v", pub2, created2, err)
	}
	info, err := os.Stat(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
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

func TestSaveAndLoadRoundTripWithoutPrivateKey(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	if _, _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	want := NodeState{ServerID: "8f0c0000-0000-4000-8000-000000000001", NodeToken: "tok", Applied: Applied{ConfigVersion: 7, ETag: `"x"`, Peers: 2}}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerID != want.ServerID || got.NodeToken != want.NodeToken || got.Applied.ConfigVersion != 7 {
		t.Fatalf("загружено %+v", got)
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

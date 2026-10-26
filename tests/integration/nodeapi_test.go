//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
	"github.com/novavpn/novavpn/internal/nodeapi"
	"github.com/novavpn/novavpn/internal/telemetry"
)

// nodeTokenShape — 32 байта crypto/rand в base64url без дополнений: ровно 43 символа
// своего алфавита и без «=». Форма, а не длина: «43 символа, но с плюсиком» был бы
// другой алфавит, и узел передал бы его дальше как Секрет без изменений.
var nodeTokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type nodeFixture struct {
	base   string
	logs   *bytes.Buffer
	ctx    context.Context
	q      *db.Queries
	server db.VpnServer
	device db.Device
}

// newNodeFixture — сквозной стенд: настоящий сборщик маршрутов (задача 18), поэтому
// конверт ошибки, журнал, 404/405 и оба лимитера те же, что в проде. Фикстура поднимает
// online-сервер с одним профилем: «узлу есть что показать», иначе desired-проверки
// тестировались бы на пустом наборе.
func newNodeFixture(t *testing.T) nodeFixture {
	t.Helper()
	srv, logs := newRouter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	q := db.New(pool(t))
	user := seedUser(t, ctx, q, true)
	server := seedServer(t, ctx, q, "10.98.20.0/24")
	setServerOnline(t, ctx, q, server.ID)
	device := seedDevice(t, ctx, q, user, 0)
	seedProfile(t, ctx, q, device.ID, server.ID, "10.98.20.2", time.Hour)
	return nodeFixture{base: srv.URL, logs: logs, ctx: ctx, q: q, server: server, device: device}
}

// secondServer — ещё один узел того же стенда: «чужой server_id» нельзя проверить на
// единственном сервере, а второй сервер стоит одной строки.
func (f nodeFixture) secondServer(t *testing.T) db.VpnServer {
	t.Helper()
	srv := seedServer(t, f.ctx, f.q, "10.98.21.0/24")
	setServerOnline(t, f.ctx, f.q, srv.ID)
	return srv
}

// TestNodeRotateSparesOtherLiveCredential — ротация гасит предъявленный токен, а не
// «все токены сервера». У узла может работать второй процесс со своим токеном
// (перезапуск без ротации), и отзыв по server_id вырубил бы его молча.
//
// Поймывает подмену RevokeNodeCredential(id) на RevokeNodeCredentialsForServer(server_id):
// при одном живом токене оба дают одинаковый результат, поэтому здесь их ровно два.
func TestNodeRotateSparesOtherLiveCredential(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)
	presented := f.enrollOK(t, raw, f.server.PublicKey)

	// Второй процесс: токен вставлен напрямую, потому что второй enroll выдал бы
	// новый и попутно отозвал предъявленный.
	parallel := secretB64(t)
	sum := sha256.Sum256([]byte(parallel))
	if _, err := f.q.InsertNodeCredential(f.ctx, db.InsertNodeCredentialParams{
		ID: uuid.New(), ServerID: f.server.ID, TokenHash: sum[:],
	}); err != nil {
		t.Fatalf("вторая строка node_credentials: %v", err)
	}

	resp, body := nodeCall(t, http.MethodPost, f.nodeURL(f.server.ID, "/token/rotate"), "", presented, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate = %d %v, want 200", resp.StatusCode, body)
	}
	fresh, _ := body["node_token"].(string)

	if resp, _ := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", presented, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("предъявленный токен после ротации = %d, want 401", resp.StatusCode)
	}
	if resp, _ := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", parallel, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("токен второго процесса после чужой ротации = %d, want 200", resp.StatusCode)
	}
	if resp, _ := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", fresh, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("новый токен ротации = %d, want 200", resp.StatusCode)
	}
	if n := liveCredentialCount(t, f.ctx, f.server.ID); n != 2 {
		t.Errorf("живых токенов после ротации %d, want 2 (второй процесс + новый)", n)
	}
}

func secretB64(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// insertBootstrap — стартовый токен так, как его выдаёт admin (задача 12): в БД
// попадает sha256, наружу — только сырое значение.
func insertBootstrap(t *testing.T, ctx context.Context, q *db.Queries, serverID uuid.UUID) (raw string, id uuid.UUID) {
	t.Helper()
	raw = secretB64(t)
	sum := sha256.Sum256([]byte(raw))
	id = uuid.New()
	if _, err := q.InsertBootstrapToken(ctx, db.InsertBootstrapTokenParams{
		ID: id, TokenHash: sum[:], ServerID: serverID, ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("InsertBootstrapToken: %v", err)
	}
	return raw, id
}

func (f nodeFixture) seedBootstrap(t *testing.T) (string, uuid.UUID) {
	t.Helper()
	return insertBootstrap(t, f.ctx, f.q, f.server.ID)
}

// expireBootstrap — просрочка одним UPDATE'ом сдвигом обоих столбцов:
// CHECK bootstrap_window требует expires_at > created_at, и «просрочить» только
// expires_at схема не даёт.
func (f nodeFixture) expireBootstrap(t *testing.T, id uuid.UUID) {
	t.Helper()
	_, err := pool(t).Exec(f.ctx,
		`UPDATE bootstrap_tokens SET created_at = now() - interval '2 hours',
		        expires_at = now() - interval '5 minutes' WHERE id = $1`, id)
	if err != nil {
		t.Fatalf("просрочка bootstrap-токена: %v", err)
	}
}

func (f nodeFixture) revokeBootstrap(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := f.q.RevokeBootstrapToken(f.ctx, id); err != nil {
		t.Fatalf("отзыв bootstrap-токена: %v", err)
	}
}

// nodeCall — запрос с телом-строкой: часть проверок требует заведомо неразбираемого
// JSON, а do() принимает только сериализуемые значения. hdrs — дополнительные
// заголовки (If-None-Match здесь нужнее всего).
func nodeCall(t *testing.T, method, url, body, bearer string, hdrs map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("тело %q не является JSON: %v", data, err)
		}
	}
	return resp, out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func (f nodeFixture) enroll(t *testing.T, raw, publicKey string) (*http.Response, map[string]any) {
	t.Helper()
	return nodeCall(t, http.MethodPost, f.base+"/internal/v1/nodes/enroll",
		mustJSON(t, map[string]string{"bootstrap_token": raw, "public_key": publicKey}), "", nil)
}

// enrollOK — enroll, обязанный выдать токен; возвращает сам токен.
func (f nodeFixture) enrollOK(t *testing.T, raw, publicKey string) string {
	t.Helper()
	resp, body := f.enroll(t, raw, publicKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll валидным токеном = %d %v, want 200", resp.StatusCode, body)
	}
	token, _ := body["node_token"].(string)
	if token == "" {
		t.Fatalf("в ответе enroll нет node_token: %v", body)
	}
	return token
}

func (f nodeFixture) nodeURL(serverID uuid.UUID, suffix string) string {
	return f.base + "/internal/v1/nodes/" + serverID.String() + suffix
}

func keyNames(t *testing.T, obj map[string]any) []string {
	t.Helper()
	var names []string
	for k := range obj {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func peerKeyNames(t *testing.T, obj map[string]any) []string {
	t.Helper()
	peers, ok := obj["peers"].([]any)
	if !ok {
		t.Fatalf("peers не массив: %T", obj["peers"])
	}
	if len(peers) != 1 {
		t.Fatalf("пиеров %d, want 1", len(peers))
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		t.Fatalf("пиер не объект: %T", peers[0])
	}
	return keyNames(t, peer)
}

func liveCredentialCount(t *testing.T, ctx context.Context, serverID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool(t).QueryRow(ctx,
		"SELECT count(*) FROM node_credentials WHERE server_id = $1 AND revoked_at IS NULL", serverID).Scan(&n); err != nil {
		t.Fatalf("подсчёт живых токенов узла: %v", err)
	}
	return n
}

func credentialHashOf(t *testing.T, ctx context.Context, serverID uuid.UUID) (hash []byte) {
	t.Helper()
	if err := pool(t).QueryRow(ctx,
		"SELECT token_hash FROM node_credentials WHERE server_id = $1 AND revoked_at IS NULL", serverID).Scan(&hash); err != nil {
		t.Fatalf("хеш токена узла: %v", err)
	}
	return hash
}

func TestNodeEnrollRefusesUnknownExpiredAndRevokedIdentically(t *testing.T) {
	f := newNodeFixture(t)
	pub := f.server.PublicKey

	respUnknown, bodyUnknown := f.enroll(t, secretB64(t), pub)
	if respUnknown.StatusCode != http.StatusUnauthorized || errorCode(t, bodyUnknown) != "unauthenticated" {
		t.Fatalf("неизвестный стартовый токен = %d %v, want 401 unauthenticated", respUnknown.StatusCode, bodyUnknown)
	}

	rawExpired, idExpired := f.seedBootstrap(t)
	f.expireBootstrap(t, idExpired)
	respExpired, bodyExpired := f.enroll(t, rawExpired, pub)
	if respExpired.StatusCode != http.StatusUnauthorized {
		t.Fatalf("просроченный токен = %d %v", respExpired.StatusCode, bodyExpired)
	}

	rawRevoked, idRevoked := f.seedBootstrap(t)
	f.revokeBootstrap(t, idRevoked)
	respRevoked, bodyRevoked := f.enroll(t, rawRevoked, pub)
	if respRevoked.StatusCode != http.StatusUnauthorized {
		t.Fatalf("отозванный токен = %d %v", respRevoked.StatusCode, bodyRevoked)
	}

	// Узел-самозванец не должен по ответу понять, что его токен хотя бы зарегистрирован:
	// все три отказа обязаны быть буквально одинаковыми.
	want := envelopePair(bodyUnknown)
	if got := envelopePair(bodyExpired); got != want {
		t.Errorf("просроченный отказ отличается от неизвестного: %q против %q", got, want)
	}
	if got := envelopePair(bodyRevoked); got != want {
		t.Errorf("отозванный отказ отличается от неизвестного: %q против %q", got, want)
	}

	logs := f.logs.String()
	for _, reason := range []string{"unknown", "expired", "revoked"} {
		if !strings.Contains(logs, `"reason":"`+reason+`"`) {
			t.Errorf("в журнале нет причины отказа %q: %s", reason, logs)
		}
	}
	for _, secret := range []string{rawExpired, rawRevoked} {
		if strings.Contains(logs, secret) {
			t.Error("в журнале оказался стартовый токен")
		}
	}
}

func TestNodeEnrollIssuesTokenOnceAndStoresOnlyHash(t *testing.T) {
	f := newNodeFixture(t)
	pub := f.server.PublicKey

	raw, _ := f.seedBootstrap(t)
	resp, body := f.enroll(t, raw, pub)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll = %d %v, want 200", resp.StatusCode, body)
	}
	token, _ := body["node_token"].(string)
	if !nodeTokenShape.MatchString(token) {
		t.Errorf("node_token %q не проходит форму base64url из 43 символов", token)
	}
	if got, _ := body["server_id"].(string); got != f.server.ID.String() {
		t.Errorf("server_id = %q, want %q", got, f.server.ID.String())
	}

	if n := liveCredentialCount(t, f.ctx, f.server.ID); n != 1 {
		t.Fatalf("живых токенов узла %d, want 1", n)
	}
	stored := credentialHashOf(t, f.ctx, f.server.ID)
	want := sha256.Sum256([]byte(token))
	if !bytes.Equal(stored, want[:]) {
		t.Error("в БД лежит не sha256 выданного токена")
	}
	var plain int
	if err := pool(t).QueryRow(f.ctx,
		"SELECT count(*) FROM node_credentials WHERE token_hash = $1", []byte(token)).Scan(&plain); err != nil {
		t.Fatal(err)
	} else if plain != 0 {
		t.Error("в БД попал сам токен узла, а не его хеш")
	}

	// Второй enroll тем же токеном — тот же отказ, что и «не знаем такого»: токен
	// одноразовый, и «уже израсходован» не должно отличаться от «не существовал».
	respUnknown, bodyUnknown := f.enroll(t, secretB64(t), pub)
	if respUnknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("неизвестный токен = %d %v", respUnknown.StatusCode, bodyUnknown)
	}
	respUsed, bodyUsed := f.enroll(t, raw, pub)
	if respUsed.StatusCode != http.StatusUnauthorized || errorCode(t, bodyUsed) != "unauthenticated" {
		t.Fatalf("повторный enroll израсходованным токеном = %d %v, want 401 unauthenticated",
			respUsed.StatusCode, bodyUsed)
	}
	if got, want := envelopePair(bodyUsed), envelopePair(bodyUnknown); got != want {
		t.Errorf("«израсходован» отличается от «неизвестен»: %q против %q", got, want)
	}
	if !strings.Contains(f.logs.String(), `"reason":"used"`) {
		t.Errorf("в журнале нет причины used: %s", f.logs.String())
	}
	if n := liveCredentialCount(t, f.ctx, f.server.ID); n != 1 {
		t.Fatalf("после отказа живых токенов %d, want 1", n)
	}
}

func TestNodeReenrollRevokesPreviousCredential(t *testing.T) {
	f := newNodeFixture(t)
	pub := f.server.PublicKey

	firstRaw, _ := f.seedBootstrap(t)
	first := f.enrollOK(t, firstRaw, pub)
	secondRaw, _ := f.seedBootstrap(t)
	second := f.enrollOK(t, secondRaw, pub)

	// Перевыпуск обязан гасить прежний токен: иначе украденный старый живёт вечно
	// рядом с новым.
	resp, body := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", first, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("прежний токен принят = %d %v, want 401", resp.StatusCode, body)
	}
	if resp, body = nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", second, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("новый токен = %d %v, want 200", resp.StatusCode, body)
	}
	if n := liveCredentialCount(t, f.ctx, f.server.ID); n != 1 {
		t.Fatalf("живых токенов узла %d, want 1", n)
	}
}

func TestNodeEnrollValidatesPublicKeyShapeAndOwnership(t *testing.T) {
	f := newNodeFixture(t)
	pub := f.server.PublicKey

	// Неканоническая запись — 400 с названием поля: это дефект запроса, а не секрета.
	raw, _ := f.seedBootstrap(t)
	resp, body := f.enroll(t, raw, nonCanonicalKey("server-"+f.server.ID.String()))
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Fatalf("неканонический ключ = %d %v, want 400 invalid_request", resp.StatusCode, body)
	}
	if details, _ := body["error"].(map[string]any)["details"].(map[string]any); details["field"] != "public_key" {
		t.Errorf("в отказе не названо поле public_key: %v", body)
	}
	// Опечатка в ключе не имеет права сжигать одноразовый токен: тот же raw должен
	// выдать токена при второй попытке.
	if f.enrollOK(t, raw, pub) == "" {
		t.Fatal("enroll после исправления ключа не прошёл")
	}

	// Канонический ключ чужого узла — отказ, неотличимый от «стартовый токен не принят».
	otherRaw, _ := f.seedBootstrap(t)
	respBad, bodyBad := f.enroll(t, otherRaw, keyFromSeed("another-node"))
	if respBad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("чужой ключ узла = %d %v, want 401", respBad.StatusCode, bodyBad)
	}
	// эталон «стартовый токен не принят» — enroll заведомо неизвестным токеном:
	// случайное значение, которого в БД нет.
	respProbe, bodyUnknown := f.enroll(t, secretB64(t), pub)
	if respProbe.StatusCode != http.StatusUnauthorized {
		t.Fatalf("проверочный enroll неизвестным токеном = %d %v, want 401", respProbe.StatusCode, bodyUnknown)
	}
	if got, want := envelopePair(bodyBad), envelopePair(bodyUnknown); got != want {
		t.Errorf("несовпадение ключа отличается от неизвестного токена: %q против %q", got, want)
	}
	if !strings.Contains(f.logs.String(), `"reason":"key_mismatch"`) {
		t.Errorf("в журнале нет причины key_mismatch: %s", f.logs.String())
	}
	// Требуется оба поля: без стартового токена enroll не имеет смысла.
	respEmpty, bodyEmpty := f.enroll(t, "", pub)
	if respEmpty.StatusCode != http.StatusBadRequest || errorCode(t, bodyEmpty) != "invalid_request" {
		t.Fatalf("пустой bootstrap_token = %d %v, want 400", respEmpty.StatusCode, bodyEmpty)
	}
}

// TestNodeEnrollKeyMismatchLeavesTokenUnspent — порядок «сверка ключа до расходования».
// Отдельным тестом, а не строкой внутри предыдущего: бакет анонимных запросов
// (burst 5) считается на тест, и шестой enroll в том же стенде упёрся бы в 429,
// что выглядело бы как отказ по ключу.
//
// Поймывает мутацию «ConsumeBootstrapToken до сравнения ключей»: тогда первая же
// попытка с чужим ключом сожгла бы стартовый токен и админ обязан перевыпускать его
// из-за опечатки, то есть ровно то, что запрещает порядок проверок из комментария к enroll.
func TestNodeEnrollKeyMismatchLeavesTokenUnspent(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)

	resp, body := f.enroll(t, raw, keyFromSeed("wrong-node"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enroll чужим ключом = %d %v, want 401", resp.StatusCode, body)
	}
	if tok := f.enrollOK(t, raw, f.server.PublicKey); tok == "" {
		t.Fatal("стартовый токен израсходован отказом по ключу")
	}
	// Отдельная проверка «used_at всё ещё NULL» здесь не нужна и была бы неверна:
	// удачный enroll как раз его и ставит. Нерастраченным токен доказывает сам
	// второй ответ — ConsumeBootstrapToken требует used_at IS NULL.
}

// nodeStandalone — тот же модуль без сборщика: обёртки «passthrough», чтобы
// одновременно пришедшие enroll'ы не упирались в бакет по IP, а споралась только
// одноразовость токена в БД.
func nodeStandalone(t *testing.T, q *db.Queries, logs *slog.Logger) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	passthrough := func(next http.Handler) http.Handler { return next }
	dec := httpx.Decorators{Auth: passthrough, Anonymous: passthrough, Node: passthrough}
	tel := telemetry.NewService(pool(t), redisClient(t), logs)
	nodeapi.NewHandler(q, tel, logs).RegisterRoutes(mux, dec)
	return mux
}

func TestNodeEnrollRaceHasOneWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	q := db.New(pool(t))
	user := seedUser(t, ctx, q, true)
	server := seedServer(t, ctx, q, "10.98.22.0/24")
	setServerOnline(t, ctx, q, server.ID)
	seedProfile(t, ctx, q, seedDevice(t, ctx, q, user, 0).ID, server.ID, "10.98.22.2", time.Hour)
	h := nodeStandalone(t, q, slog.New(slog.NewJSONHandler(io.Discard, nil)))

	raw, _ := insertBootstrap(t, ctx, q, server.ID)
	body := mustJSON(t, map[string]string{"bootstrap_token": raw, "public_key": server.PublicKey})

	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/internal/v1/nodes/enroll", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if codes[http.StatusOK] != 1 {
		t.Fatalf("успешных enroll из десяти: %d (все коды %v), want ровно 1", codes[http.StatusOK], codes)
	}
	for code, n := range codes {
		if n > 0 && code != http.StatusOK && code != http.StatusUnauthorized {
			t.Errorf("код %d x%d: отказ обязан быть 401, все коды %v", code, n, codes)
		}
	}
	if n := liveCredentialCount(t, ctx, server.ID); n != 1 {
		t.Fatalf("живых токенов узла после гонки %d, want 1", n)
	}
}

func TestNodeRoutesRequireNodeToken(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)
	token := f.enrollOK(t, raw, f.server.PublicKey)
	load := 1.2
	report := telemetry.ObservedReport{ConfigVersion: 1, AppliedAt: time.Now().UTC(),
		Peers: []telemetry.PeerStat{{PublicKey: f.device.PublicKey, RxBytes: 10, TxBytes: 5}}}
	heartbeat := telemetry.Heartbeat{AgentVersion: "0.9.1", AgentUptimeSec: 42, AppliedConfigVersion: 1, Load1: &load}

	routes := []struct{ method, suffix, body string }{
		{http.MethodGet, "/desired", ""},
		{http.MethodPost, "/observed", mustJSON(t, report)},
		{http.MethodPost, "/heartbeat", mustJSON(t, heartbeat)},
		{http.MethodPost, "/token/rotate", ""},
	}
	base := f.nodeURL(f.server.ID, "")

	var want string
	for i, rt := range routes {
		resp, body := nodeCall(t, rt.method, base+rt.suffix, rt.body, "", nil)
		if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "unauthenticated" {
			t.Fatalf("%s %s без токена = %d %v, want 401 unauthenticated", rt.method, rt.suffix, resp.StatusCode, body)
		}
		if i == 0 {
			want = envelopePair(body)
		}
		// «Не знаем такого», «отозван» и «битый формат» — один ответ на всех:
		// по разнице кодов узел-самозванец понимал бы, что токен зарегистрирован.
		respGarbage, bodyGarbage := nodeCall(t, rt.method, base+rt.suffix, rt.body, "000000000000000000000000000000000000000", nil)
		if respGarbage.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s битым токеном = %d %v", rt.method, rt.suffix, respGarbage.StatusCode, bodyGarbage)
		}
		if got := envelopePair(bodyGarbage); got != want {
			t.Errorf("%s %s: отказ на битом токене отличается от отказа без токена: %q против %q",
				rt.method, rt.suffix, got, want)
		}
	}

	// Принятый запрос отмечен в строке токена: отзыв «неиспользуемого» (задача 12)
	// слеп без last_used_at.
	if resp, body := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("desired валидным токеном = %d %v, want 200", resp.StatusCode, body)
	}
	var used int
	if err := pool(t).QueryRow(f.ctx,
		"SELECT count(*) FROM node_credentials WHERE server_id = $1 AND last_used_at IS NOT NULL", f.server.ID).Scan(&used); err != nil {
		t.Fatal(err)
	} else if used != 1 {
		t.Fatalf("токенов с last_used_at = %d, want 1", used)
	}

	// Отзыв токена = мгновенный отказ, без ожидания истечения.
	if _, err := pool(t).Exec(f.ctx,
		"UPDATE node_credentials SET revoked_at = now() WHERE server_id = $1", f.server.ID); err != nil {
		t.Fatalf("отзыв токена узла: %v", err)
	}
	resp, body := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", token, nil)
	if resp.StatusCode != http.StatusUnauthorized || envelopePair(body) != want {
		t.Fatalf("отозванный токен = %d %v, want тот же 401, что и без токена", resp.StatusCode, body)
	}
}

func TestNodeRoutesRejectForeignServerID(t *testing.T) {
	f := newNodeFixture(t)
	other := f.secondServer(t)

	rawSelf, _ := f.seedBootstrap(t)
	self := f.enrollOK(t, rawSelf, f.server.PublicKey)
	rawOther, _ := insertBootstrap(t, f.ctx, f.q, other.ID)
	otherToken := f.enrollOK(t, rawOther, other.PublicKey)

	routes := []struct{ method, suffix, body string }{
		{http.MethodGet, "/desired", ""},
		{http.MethodPost, "/observed", mustJSON(t, telemetry.ObservedReport{ConfigVersion: 1, AppliedAt: time.Now().UTC()})},
		{http.MethodPost, "/heartbeat", mustJSON(t, telemetry.Heartbeat{AgentVersion: "0.9.1", AgentUptimeSec: 1})},
		{http.MethodPost, "/token/rotate", ""},
	}
	// Свой токен и чужой server_id в пути — 403: узел не имеет права читать набор
	// чужого узла и писать телеметрию в его статистику.
	for _, rt := range routes {
		resp, body := nodeCall(t, rt.method, f.nodeURL(other.ID, rt.suffix), rt.body, self, nil)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, body) != "forbidden" {
			t.Fatalf("%s %s чужим путём = %d %v, want 403 forbidden", rt.method, rt.suffix, resp.StatusCode, body)
		}
	}
	// Чужой токен и свой путь — тоже 403: проверка «токен == путь», а не «токен свой».
	resp, body := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", otherToken, nil)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, body) != "forbidden" {
		t.Fatalf("desired чужим токеном = %d %v, want 403 forbidden", resp.StatusCode, body)
	}
	// Тот же чужой токен на своём пути работает: 403 — про путь, а не про «незнакомый токен».
	if resp, body = nodeCall(t, http.MethodGet, f.nodeURL(other.ID, "/desired"), "", otherToken, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("desired своим путём = %d %v, want 200", resp.StatusCode, body)
	}
	// Несуществующий сервер с валидным токеном — 403, а не 404: различать «такого
	// сервера нет» узлу не за чем.
	resp, body = nodeCall(t, http.MethodGet, f.nodeURL(uuid.New(), "/desired"), "", self, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("desired неизвестного сервера = %d %v, want 403", resp.StatusCode, body)
	}
	// Путь, где вместо id мусор — 400 с названием поля.
	resp, body = nodeCall(t, http.MethodGet, f.base+"/internal/v1/nodes/ne-server/desired", "", self, nil)
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Fatalf("desired с не-UUID в пути = %d %v, want 400 invalid_request", resp.StatusCode, body)
	}
}

func TestNodeDesiredETagAndFieldNames(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)
	token := f.enrollOK(t, raw, f.server.PublicKey)

	resp, set := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("desired = %d %v, want 200", resp.StatusCode, set)
	}
	etag := resp.Header.Get("ETag")
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || len(etag) < 3 {
		t.Fatalf("ETag %q не в кавычках по RFC 9110", etag)
	}
	if got, want := keyNames(t, set), []string{"config_version", "dns_servers", "keepalive_sec", "listen_port", "measured_at", "mtu", "peers", "server_id"}; !slices.Equal(got, want) {
		t.Errorf("имена полей desired = %v, want %v", got, want)
	}
	if got, want := peerKeyNames(t, set), []string{"allowed_ips", "expires_at", "public_key", "state"}; !slices.Equal(got, want) {
		t.Errorf("имена полей пиера = %v, want %v", got, want)
	}
	// Приватных ключей в ответе нет: desired — набор пиеров, а не материал узла.
	raw2, _ := json.Marshal(set)
	for _, forbidden := range []string{"private_key", "preshared", "psk"} {
		if strings.Contains(strings.ToLower(string(raw2)), forbidden) {
			t.Errorf("в ответе desired встречается %q", forbidden)
		}
	}

	// Совпавший If-None-Match — 304 без тела и без Content-Type.
	resp304, body304 := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", token,
		map[string]string{"If-None-Match": etag})
	if resp304.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match = %d %v, want 304", resp304.StatusCode, body304)
	}
	if len(body304) != 0 {
		t.Errorf("304 вернул тело: %v", body304)
	}
	if ct := resp304.Header.Get("Content-Type"); ct != "" {
		t.Errorf("у 304 стоит Content-Type %q", ct)
	}
	// Другой ETag не должен привести к 304: сравнение строгое, без префиксов и W/.
	resp, _ = nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", token,
		map[string]string{"If-None-Match": `"v999999"`})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("несовпавший If-None-Match = %d, want 200", resp.StatusCode)
	}
}

// TestNodeDesiredETagChangesWhenHandshakeClosesOverlap — ETag обязан зависеть от
// содержимого набора: закрытие overlap-окна handshake'ем не поднимает
// config_version, и с версионным ETag узел получал бы 304 и держал старый ключ
// вопреки §7.3 («как только агент наблюдал handshake от нового ключа, старый
// снимается немедленно»).
func TestNodeDesiredETagChangesWhenHandshakeClosesOverlap(t *testing.T) {
	f := newNodeFixture(t)
	srv := f.secondServer(t)
	user := seedUser(t, f.ctx, f.q, true)
	parent := seedDevice(t, f.ctx, f.q, user, 0)
	seedProfile(t, f.ctx, f.q, parent.ID, srv.ID, "10.98.21.2", time.Hour)
	svc := devices.NewService(pool(t), entitlements.New(f.q))
	child, err := svc.RotateKey(f.ctx, user, parent.ID, keyFromSeed("etag-"+parent.ID.String()))
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	raw, _ := insertBootstrap(t, f.ctx, f.q, srv.ID)
	token := f.enrollOK(t, raw, srv.PublicKey)

	resp, set := nodeCall(t, http.MethodGet, f.nodeURL(srv.ID, "/desired"), "", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("desired = %d %v, want 200", resp.StatusCode, set)
	}
	etag := resp.Header.Get("ETag")
	if !hasPeerState(set, "rotating_old_key") {
		t.Fatalf("в наборе нет старого ключа: %v", set["peers"])
	}

	if _, err := pool(t).Exec(f.ctx,
		`INSERT INTO connection_events (user_id, device_id, server_id, event)
		 VALUES ($1, $2, $3, 'handshake_observed')`, user, child.ID, srv.ID); err != nil {
		t.Fatalf("событие handshake: %v", err)
	}

	resp2, set2 := nodeCall(t, http.MethodGet, f.nodeURL(srv.ID, "/desired"), "", token,
		map[string]string{"If-None-Match": etag})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("If-None-Match после handshake = %d %v, want 200: набор изменился, версия — нет",
			resp2.StatusCode, set2)
	}
	if got := resp2.Header.Get("ETag"); got == etag {
		t.Errorf("ETag не изменился после снятия старого ключа: %q", got)
	}
	if hasPeerState(set2, "rotating_old_key") {
		t.Errorf("старый ключ остался в наборе после handshake: %v", set2["peers"])
	}
}

// hasPeerState — есть ли в ответе desired пиер с состоянием state.
func hasPeerState(set map[string]any, state string) bool {
	peers, _ := set["peers"].([]any)
	for _, raw := range peers {
		peer, _ := raw.(map[string]any)
		if peer["state"] == state {
			return true
		}
	}
	return false
}

func TestNodeDesiredGrowsWithIssuedProfile(t *testing.T) {
	f := newNodeFixture(t)
	empty := f.secondServer(t)

	raw, _ := insertBootstrap(t, f.ctx, f.q, empty.ID)
	token := f.enrollOK(t, raw, empty.PublicKey)

	resp, set := nodeCall(t, http.MethodGet, f.nodeURL(empty.ID, "/desired"), "", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("desired пустого узла = %d %v", resp.StatusCode, set)
	}
	peers, ok := set["peers"].([]any)
	if !ok || len(peers) != 0 {
		t.Fatalf("на сервере без профилей peers = %#v, want пустой массив", set["peers"])
	}
	first := resp.Header.Get("ETag")

	user := seedUser(t, f.ctx, f.q, true)
	device := seedDevice(t, f.ctx, f.q, user, 0)
	seedProfile(t, f.ctx, f.q, device.ID, empty.ID, "10.98.21.2", time.Hour)
	version, err := f.q.BumpServerConfigVersion(f.ctx, empty.ID)
	if err != nil {
		t.Fatalf("BumpServerConfigVersion: %v", err)
	}

	resp2, set2 := nodeCall(t, http.MethodGet, f.nodeURL(empty.ID, "/desired"), "", token, nil)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("desired после выдачи = %d %v", resp2.StatusCode, set2)
	}
	if v, _ := set2["config_version"].(float64); v != float64(version) {
		t.Errorf("config_version = %v, want %d", set2["config_version"], version)
	}
	if got := resp2.Header.Get("ETag"); got == first {
		t.Errorf("ETag не изменился после выдачи профиля: %q", got)
	}
	peers2, ok := set2["peers"].([]any)
	if !ok || len(peers2) != 1 {
		t.Fatalf("пиеров после выдачи %v, want 1", set2["peers"])
	}
	if key, _ := peers2[0].(map[string]any)["public_key"].(string); key != device.PublicKey {
		t.Errorf("пиер = %q, want публичный ключ выданного устройства %q", key, device.PublicKey)
	}
	// If-None-Match прежним ETag'ом после изменения набора не даёт 304.
	resp3, _ := nodeCall(t, http.MethodGet, f.nodeURL(empty.ID, "/desired"), "", token,
		map[string]string{"If-None-Match": first})
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("условный запрос старым ETag после выдачи = %d, want 200", resp3.StatusCode)
	}
}

func TestNodeObservedAndHeartbeatFillHealth(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)
	token := f.enrollOK(t, raw, f.server.PublicKey)

	handshaked := time.Now().UTC().Add(-time.Second)
	report := telemetry.ObservedReport{
		ConfigVersion: 3, InterfaceRxBytes: 1000, InterfaceTxBytes: 500,
		AppliedAt: time.Now().UTC(), Peers: []telemetry.PeerStat{
			{PublicKey: f.device.PublicKey, LatestHandshake: &handshaked, RxBytes: 1000, TxBytes: 500}}}
	resp, body := nodeCall(t, http.MethodPost, f.nodeURL(f.server.ID, "/observed"), mustJSON(t, report), token, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("observed = %d %v, want 204", resp.StatusCode, body)
	}
	if len(body) != 0 {
		t.Errorf("204 вернул тело: %v", body)
	}
	h, err := f.q.ServerHealthOf(f.ctx, f.server.ID)
	if err != nil {
		t.Fatalf("health после observed: %v", err)
	}
	if h.PeersConfigured != 1 || h.PeersHandshaked != 1 || h.InterfaceRxBytes != 1000 || h.InterfaceTxBytes != 500 ||
		h.AppliedConfigVersion != 3 {
		t.Fatalf("набраз живого узла: %+v", h)
	}
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 1 {
		t.Fatalf("событий handshake: %d, want 1", n)
	}
	if rows, _, _ := telemetryTraffic(t, f.device.ID); rows != 0 {
		t.Fatalf("первый отчёт начислил трафик: %d строк", rows)
	}

	load, cpu := 0.5, 12.25
	hb := telemetry.Heartbeat{AgentVersion: "1.0.0", AgentUptimeSec: 3600, Load1: &load, CPUPct: &cpu,
		AppliedConfigVersion: 3}
	resp, body = nodeCall(t, http.MethodPost, f.nodeURL(f.server.ID, "/heartbeat"), mustJSON(t, hb), token, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("heartbeat = %d %v, want 204", resp.StatusCode, body)
	}
	h2, err := f.q.ServerHealthOf(f.ctx, f.server.ID)
	if err != nil {
		t.Fatalf("health после heartbeat: %v", err)
	}
	// Heartbeat не имеет права затирая пиерные колонки: их приносит только observed.
	if h2.AgentVersion == nil || *h2.AgentVersion != "1.0.0" {
		t.Fatalf("версия агента не записана: %+v", h2)
	}
	if h2.PeersConfigured != 1 || h2.PeersHandshaked != 1 || h2.InterfaceRxBytes != 1000 || h2.InterfaceTxBytes != 500 {
		t.Fatalf("heartbeat стёр наблюдение: %+v", h2)
	}
	// numeric(6,3) и numeric(5,2): PostgreSQL отдаёт значение с масштабом колонки,
	// поэтому «0.5» в health живёт как "0.500" — ровно как в тесте задачи 10.
	if h2.Load1 == nil || *h2.Load1 != "0.500" || h2.CpuPct == nil || *h2.CpuPct != "12.25" {
		t.Fatalf("метрики heartbeat: %+v", h2)
	}
}

func TestNodeObservedAndHeartbeatRejectBadPayloads(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)
	token := f.enrollOK(t, raw, f.server.PublicKey)
	observed := f.nodeURL(f.server.ID, "/observed")

	// Отказ обязан наступить до любой записи: «приняли половину отчёта» здесь нет.
	refs := []struct{ name, method, url, body string }{
		{"неразбираемый JSON", http.MethodPost, observed, "{не json"},
		{"отрицательный rx_bytes", http.MethodPost, observed, mustJSON(t, telemetry.ObservedReport{
			ConfigVersion: 1, AppliedAt: time.Now().UTC(),
			Peers: []telemetry.PeerStat{{PublicKey: f.device.PublicKey, RxBytes: -1}}})},
		{"пиеров больше потолка", http.MethodPost, observed, mustJSON(t, telemetry.ObservedReport{
			ConfigVersion: 1, AppliedAt: time.Now().UTC(), Peers: peerStats(telemetry.MaxReportPeers + 1)})},
		{"неизвестное поле в теле", http.MethodPost, observed, mustJSON(t, map[string]any{
			"config_version": 1, "peers": []any{}, "server_id": f.server.ID.String()})},
		{"пустой agent_version", http.MethodPost, f.nodeURL(f.server.ID, "/heartbeat"),
			mustJSON(t, telemetry.Heartbeat{AgentVersion: "", AgentUptimeSec: 1})},
		{"cpu_pct за пределами", http.MethodPost, f.nodeURL(f.server.ID, "/heartbeat"),
			mustJSON(t, telemetry.Heartbeat{AgentVersion: "1.0.0", AgentUptimeSec: 1, CPUPct: ptr(120.0)})},
	}
	for _, ref := range refs {
		resp, body := nodeCall(t, ref.method, ref.url, ref.body, token, nil)
		if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
			t.Errorf("%s: %d %v, want 400 invalid_request", ref.name, resp.StatusCode, body)
		}
	}
	var healthRows int
	if err := pool(t).QueryRow(f.ctx, "SELECT count(*) FROM server_health WHERE server_id = $1", f.server.ID).Scan(&healthRows); err != nil {
		t.Fatal(err)
	}
	if healthRows != 0 {
		t.Fatalf("после отказов в health %d строк, want 0", healthRows)
	}
	// Битое тело — это 400, а не 500: отказ разбора не обязан превращаться во внутреннюю ошибку.
	resp, body := nodeCall(t, http.MethodPost, observed, mustJSON(t, telemetry.ObservedReport{
		ConfigVersion: 1, AppliedAt: time.Now().UTC()}), token, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("пустой отчёт = %d %v, want 204", resp.StatusCode, body)
	}
}

func peerStats(n int) []telemetry.PeerStat {
	peers := make([]telemetry.PeerStat, n)
	for i := range peers {
		peers[i] = telemetry.PeerStat{PublicKey: keyFromSeed("peer-" + strconv.Itoa(i))}
	}
	return peers
}

func ptr(v float64) *float64 { return &v }

func TestNodeTokenRotateReplacesPresentedCredential(t *testing.T) {
	f := newNodeFixture(t)
	firstRaw, _ := f.seedBootstrap(t)
	first := f.enrollOK(t, firstRaw, f.server.PublicKey)

	resp, body := nodeCall(t, http.MethodPost, f.nodeURL(f.server.ID, "/token/rotate"), "", first, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate = %d %v, want 200", resp.StatusCode, body)
	}
	second, _ := body["node_token"].(string)
	if !nodeTokenShape.MatchString(second) {
		t.Fatalf("новый токен %q не проходит форму", second)
	}
	if got, _ := body["server_id"].(string); got != f.server.ID.String() {
		t.Errorf("server_id = %q, want %q", got, f.server.ID.String())
	}
	if second == first {
		t.Error("ротация вернула тот же токен")
	}

	if resp, body = nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", first, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("прежний токен после ротации принят = %d %v, want 401", resp.StatusCode, body)
	}
	if resp, body = nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", second, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("новый токен = %d %v, want 200", resp.StatusCode, body)
	}

	firstID := credentialID(t, f.ctx, first)
	rotatedFrom := credentialRotatedFrom(t, f.ctx, second)
	if rotatedFrom == nil || *rotatedFrom != firstID {
		t.Fatalf("rotated_from = %v, want id прежнего токена %v", rotatedFrom, firstID)
	}
	if revoked := credentialRevokedAt(t, f.ctx, firstID); revoked == nil {
		t.Error("прежний токен не отозван ротацией")
	}
	if n := liveCredentialCount(t, f.ctx, f.server.ID); n != 1 {
		t.Fatalf("живых токенов после ротации %d, want 1", n)
	}

	// Цепочка: вторая ротация ссылается на второй токен, а не на первый.
	resp, body = nodeCall(t, http.MethodPost, f.nodeURL(f.server.ID, "/token/rotate"), "", second, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("вторая ротация = %d %v", resp.StatusCode, body)
	}
	third, _ := body["node_token"].(string)
	if got := credentialRotatedFrom(t, f.ctx, third); got == nil || *got != credentialID(t, f.ctx, second) {
		t.Fatalf("rotated_from второй ротации = %v", got)
	}
	if n := liveCredentialCount(t, f.ctx, f.server.ID); n != 1 {
		t.Fatalf("живых токенов после второй ротации %d, want 1", n)
	}
}

func credentialID(t *testing.T, ctx context.Context, token string) uuid.UUID {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	var id uuid.UUID
	if err := pool(t).QueryRow(ctx, "SELECT id FROM node_credentials WHERE token_hash = $1", sum[:]).Scan(&id); err != nil {
		t.Fatalf("id токена узла: %v", err)
	}
	return id
}

func credentialRotatedFrom(t *testing.T, ctx context.Context, token string) *uuid.UUID {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	var from *uuid.UUID
	if err := pool(t).QueryRow(ctx, "SELECT rotated_from FROM node_credentials WHERE token_hash = $1", sum[:]).Scan(&from); err != nil {
		t.Fatalf("rotated_from токена узла: %v", err)
	}
	return from
}

func credentialRevokedAt(t *testing.T, ctx context.Context, id uuid.UUID) *time.Time {
	t.Helper()
	var revoked *time.Time
	if err := pool(t).QueryRow(ctx, "SELECT revoked_at FROM node_credentials WHERE id = $1", id).Scan(&revoked); err != nil {
		t.Fatalf("revoked_at токена узла: %v", err)
	}
	return revoked
}

func TestNodeDesiredRateLimitedPerServer(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)
	token := f.enrollOK(t, raw, f.server.PublicKey)

	firstLimited, retryAfter := 0, ""
	for i := 1; i <= 130; i++ {
		resp, _ := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", token, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			firstLimited, retryAfter = i, resp.Header.Get("Retry-After")
			break
		}
	}
	if firstLimited == 0 {
		t.Fatal("130 запросов одного узла не уперлись в лимит 120 в минуту")
	}
	// Порядок обёрток: бакет узла (burst 10) обязан сработать раньше базового окна по
	// IP (burst 60), иначе «120 в минуту для узла» — число, которого в сборке нет.
	if firstLimited > 15 {
		t.Fatalf("первый 429 на запросе %d: сработало окно по IP, а не бакет узла", firstLimited)
	}
	if n, err := strconv.Atoi(retryAfter); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want целое число секунд >= 1", retryAfter)
	}
}

// TestNodeRateLimitIsPerServer — бакет «на узел», а не «на сборку»: запросы одного
// vpn-сервера не имеют права отнимать бюджет у другого. Поймывает обратный порядок
// обёрток (лимитер до аутентификации): тогда ключ бакета у обоих запросов — "unknown"
// и второй узел получает 429 от чужого переполнения.
//
// Перебор делается ровно до первого 429, а не фиксированным числом запросов: базовое
// окно по IP (burst 60) стоит перед диспетчером и тоже тратит токены, поэтому 130
// подряд оставили бы проверку в зависимости от скорости цикла, а не от порядка обёрток.
func TestNodeRateLimitIsPerServer(t *testing.T) {
	f := newNodeFixture(t)
	rawA, _ := f.seedBootstrap(t)
	tokenA := f.enrollOK(t, rawA, f.server.PublicKey)

	serverB := f.secondServer(t)
	rawB, _ := insertBootstrap(t, f.ctx, f.q, serverB.ID)
	tokenB := f.enrollOK(t, rawB, serverB.PublicKey)

	limitedAt := 0
	for i := 1; i <= 30; i++ {
		resp, _ := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", tokenA, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			limitedAt = i
			break
		}
	}
	if limitedAt == 0 {
		t.Fatal("30 запросов узла A не исчерпали его бакет — проверять нечего")
	}

	// Узел B обращается впервые: у него полный бакет, и 429 здесь означал бы, что
	// бюджет считается не по серверу.
	if resp, body := nodeCall(t, http.MethodGet, f.nodeURL(serverB.ID, "/desired"), "", tokenB, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("desired узла B после переполнения бакета A = %d %v, want 200", resp.StatusCode, body)
	}
	// И наоборот: A обязан оставаться ограниченным, иначе B прошёл бы только
	// потому, что лимитер снялся целиком.
	if resp, _ := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", tokenA, nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("узел A после 429 снова получил %d, want 429", resp.StatusCode)
	}
}

// requestLines разбирает строки журнала и оставляет только строки запроса
// (msg=request) по имени маршрута. Нужен именно разбор, а не Contains: сервисы
// пишут собственные строки с server_id (например telemetry: heartbeat accepted),
// и поиск по всему буферу нашёл бы server_id даже тогда, когда Accumulator запроса
// его не получил вовсе.
func requestLines(t *testing.T, logs string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("строка журнала не JSON: %v (%s)", err, line)
		}
		if entry["msg"] == "request" {
			route, _ := entry["route"].(string)
			out[route] = entry
		}
	}
	return out
}

func TestNodeJournalCarriesServerIDAndNoTokens(t *testing.T) {
	f := newNodeFixture(t)
	raw, _ := f.seedBootstrap(t)
	token := f.enrollOK(t, raw, f.server.PublicKey)
	f.logs.Reset()

	if resp, body := nodeCall(t, http.MethodGet, f.nodeURL(f.server.ID, "/desired"), "", token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("desired = %d %v", resp.StatusCode, body)
	}
	load := 0.25
	if resp, body := nodeCall(t, http.MethodPost, f.nodeURL(f.server.ID, "/heartbeat"),
		mustJSON(t, telemetry.Heartbeat{AgentVersion: "1.0.0", AgentUptimeSec: 10, Load1: &load}), token, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("heartbeat = %d %v", resp.StatusCode, body)
	}

	logs := f.logs.String()
	lines := requestLines(t, logs)
	for _, route := range []string{
		"GET /internal/v1/nodes/{server_id}/desired",
		"POST /internal/v1/nodes/{server_id}/heartbeat",
	} {
		entry, ok := lines[route]
		if !ok {
			t.Fatalf("в журнале нет строки запроса %s: %s", route, logs)
		}
		// Субъект строки запроса — сервер, а не человек: без этого поля журнал
		// не отвечает на «кто стучался», и матрица задача 15 нечем проверяется.
		if sid, _ := entry["server_id"].(string); sid != f.server.ID.String() {
			t.Errorf("%s: server_id = %q, want %q", route, sid, f.server.ID.String())
		}
		if id, _ := entry["request_id"].(string); len(id) != 16 {
			t.Errorf("%s: request_id = %q, want 16 hex", route, id)
		}
	}
	for _, secret := range []string{raw, token} {
		if strings.Contains(logs, secret) {
			t.Error("в журнал попал токен (стартовый или узловой)")
		}
	}
	if strings.Contains(strings.ToLower(logs), "authorization") {
		t.Error("журнал упоминает заголовок Authorization")
	}
}

package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// chain — тот же порядок, что соберёт api.NewRouter, минус базовый лимитер по IP
// (он проверяется интеграционным тестом сборки): request id, журнал, конверт.
// mux передаётся дважды: журналу он нужен, чтобы назвать маршрут до диспетчера,
// а Envelope — чтобы этот диспетчер найти.
func chain(mux *http.ServeMux, log *slog.Logger) http.Handler {
	return NewRequestID(Logging(Envelope(mux), mux, log))
}

// jsonLine читает первую строку журнала: паника и предупреждения добавляют свои
// строки, и тесты про журнал обязаны отличаться от тестов про панику именно этим.
func jsonLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := bytes.TrimSpace(buf.Bytes())
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("journal must start with one JSON line: %v (%q)", err, buf.String())
	}
	return entry
}

func envelopeCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var got struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q is not the documented envelope: %v", w.Body, err)
	}
	if !isHex16(got.Error.RequestID) {
		t.Errorf("request_id %q must be 16 hex chars", got.Error.RequestID)
	}
	return got.Error.Code
}

func TestLoggingNamesRouteStatusUserAndWritesOneLine(t *testing.T) {
	var buf bytes.Buffer
	user := uuid.New()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		// Так делает auth.Middleware: subject известен только внутри обработчика.
		// Новый контекст здесь не обязателен: аккумулятор живёт в старом ctx
		// и доступен по указателю.
		_ = WithUserID(r.Context(), user)
		_, _ = w.Write([]byte("ok"))
	})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("matched route: %d %q", w.Code, w.Body.String())
	}

	// Ровно одна строка: если NewRequestID всё ещё пишет свою «http», тест ловит
	// это здесь, а не через неделю, когда журнал начнут парсить.
	if n := bytes.Count(bytes.TrimSpace(buf.Bytes()), []byte("\n")) + 1; n != 1 {
		t.Fatalf("journal lines = %d, want 1: %s", n, buf.String())
	}

	entry := jsonLine(t, &buf)
	want := map[string]string{
		"msg":     "request",
		"method":  "GET",
		"route":   "GET /api/v1/me",
		"user_id": user.String(),
	}
	for k, v := range want {
		if got, _ := entry[k].(string); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if entry["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200", entry["status"])
	}
	if id, _ := entry["request_id"].(string); !isHex16(id) {
		t.Errorf("request_id = %q, want 16 hex chars", id)
	}
	if _, ok := entry["dur_ms"].(float64); !ok {
		t.Error("dur_ms must be a number: §5.2 требует длительность")
	}
}

func TestEnvelopeNotFoundHasEnvelopeAndUnmatchedRoute(t *testing.T) {
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/nothing?token=super-secret-value", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if code := envelopeCode(t, w); code != "not_found" {
		t.Errorf("code = %q, want not_found", code)
	}
	// 404 не имеет права врать про Allow: этот путь не принимает никакой метод.
	if w.Header().Get("Allow") != "" {
		t.Errorf("Allow = %q, want empty for 404", w.Header().Get("Allow"))
	}

	entry := jsonLine(t, &buf)
	// Путь клиента в журнале отсутствует намеренно: это единственное место, где
	// чужой запрос мог бы протащить в лог токен из query-строки.
	if entry["route"] != "unmatched" {
		t.Errorf("route = %v, want unmatched", entry["route"])
	}
	if entry["status"] != float64(http.StatusNotFound) {
		t.Errorf("status = %v, want 404", entry["status"])
	}
	if _, ok := entry["user_id"]; ok {
		t.Error("user_id must be absent when nobody is authenticated")
	}

	lower := strings.ToLower(buf.String())
	if strings.Contains(lower, "super-secret-value") {
		t.Error("journal contains the query string")
	}
	for _, forbidden := range []string{"authorization", "password", "refresh_token", "token="} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("journal mentions %q", forbidden)
		}
	}
}

func TestEnvelopeMethodNotAllowedListsAllowedMethods(t *testing.T) {
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/devices", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /api/v1/devices", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodPut, "/api/v1/devices", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if code := envelopeCode(t, w); code != "method_not_allowed" {
		t.Errorf("code = %q, want method_not_allowed", code)
	}
	// HEAD обязателен: ServeMux принимает HEAD на зарегистрированный GET, и Allow
	// без HEAD обещал бы меньше, чем сервер действительно принимает.
	allow := w.Header().Get("Allow")
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		if !strings.Contains(allow, m) {
			t.Errorf("Allow = %q, missing %s", allow, m)
		}
	}
	if strings.Contains(allow, http.MethodPut) {
		t.Errorf("Allow = %q contains the rejected method", allow)
	}
	if entry := jsonLine(t, &buf); entry["status"] != float64(http.StatusMethodNotAllowed) {
		t.Errorf("journal status = %v, want 405", entry["status"])
	}
}

func TestEnvelopeTrailingSlashIsNotFound(t *testing.T) {
	// Go не делает из "/api/v1/devices/" редирект на "/api/v1/devices": pattern
	// пустой. Значит ответ формирует Envelope, и это конверт, а не текст.
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/devices/", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d %q, want 404", w.Code, w.Body.String())
	}
	if code := envelopeCode(t, w); code != "not_found" {
		t.Errorf("code = %q, want not_found", code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, API не должен делать из маршрута тихую переадресацию", loc)
	}
}

func TestEnvelopeKeepsServeMuxPathCleanupRedirect(t *testing.T) {
	// "/api/v1//devices" Go чистит и отвечает 301 сам; pattern при этом —
	// зарегистрированный маршрут. Envelope обязан пропустить этот handler:
	// редирект не скрывает токенов и не ломает формат ошибок (тела у 301 нет).
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1//devices", nil))
	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d %q, want 301", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/api/v1/devices" {
		t.Errorf("Location = %q, want /api/v1/devices", loc)
	}
	// В журнале — шаблон, а не путь клиента: двойная косая черта туда не попадает.
	if entry := jsonLine(t, &buf); entry["route"] != "GET /api/v1/devices" {
		t.Errorf("route = %v, want GET /api/v1/devices", entry["route"])
	}
}

func TestLoggingRecoversPanicWithEnvelope(t *testing.T) {
	// http.Server переживает панику сам, но соединение при этом обрывается, а
	// журнал не пишется вовсе. Клиент обязан получить конверт, а ops — строку.
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/boom", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("panic must answer 500, got %d", w.Code)
	}
	if code := envelopeCode(t, w); code != "internal" {
		t.Errorf("code = %q, want internal", code)
	}
	line := buf.String()
	if !strings.Contains(line, `"route":"GET /api/v1/boom"`) {
		t.Errorf("journal must name the route of the crashed handler: %s", line)
	}
	if !strings.Contains(line, `"status":500`) {
		t.Errorf("journal must record 500: %s", line)
	}
	if !strings.Contains(line, "boom") {
		t.Errorf("panic reason must reach the journal: %s", line)
	}
}

func TestEnvelopePassesWildcardPathValuesToHandler(t *testing.T) {
	// Диспетчер обязан идти через ServeHTTP самого mux: значения сегментов пути
	// ({id}) проставляет только ServeMux.ServeHTTP, а Handler(r) лишь говорит,
	// какой handler выиграл. Вызов «выигравшего» напрямую оставлял
	// r.PathValue("id") пустым, то есть каждый маршрут с id в пути отвечал 400 на
	// собственный же путь. Через Envelope это видно только здесь: тесты модулей
	// строят mux сами и проходят мимо конверта.
	const id = "11111111-1111-1111-1111-111111111111"
	mux := http.NewServeMux()
	got := make(chan string, 1)
	mux.HandleFunc("DELETE /api/v1/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		got <- r.PathValue("id")
		w.WriteHeader(http.StatusNoContent)
	})

	w := httptest.NewRecorder()
	Envelope(mux).ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+id, nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d %q, want 204", w.Code, w.Body.String())
	}
	if v := <-got; v != id {
		t.Errorf("PathValue(\"id\") = %q, want %q из пути", v, id)
	}
}

func TestEnvelopeWorksWithoutLogging(t *testing.T) {
	// noteRoute обязан молчать без журнала: Envelope используется и в тестах
	// модулей, где Logging не подключён.
	mux := http.NewServeMux()
	w := httptest.NewRecorder()
	Envelope(mux).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestWithUserIDWithoutJournalDoesNotPanic(t *testing.T) {
	id := uuid.New()
	ctx := WithUserID(context.Background(), id)
	got, ok := UserIDFromContext(ctx)
	if !ok || got != id {
		t.Errorf("UserIDFromContext = (%v, %v), want (%v, true)", got, ok, id)
	}
}

package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

type memoryIdempotency struct {
	entries   map[string]db.IdempotencyKey
	completed int
	abandoned int
}

func memorySlot(userID uuid.UUID, route, key string) string {
	return userID.String() + "/" + route + "/" + key
}

func (m *memoryIdempotency) Claim(_ context.Context, userID uuid.UUID, route, key string, hash []byte) (db.IdempotencyKey, bool, error) {
	if m.entries == nil {
		m.entries = make(map[string]db.IdempotencyKey)
	}
	slot := memorySlot(userID, route, key)
	if existing, ok := m.entries[slot]; ok {
		return existing, true, nil
	}
	m.entries[slot] = db.IdempotencyKey{RequestHash: hash}
	return db.IdempotencyKey{}, false, nil
}

func (m *memoryIdempotency) Complete(_ context.Context, userID uuid.UUID, route, key string, status int, body []byte) error {
	entry := m.entries[memorySlot(userID, route, key)]
	statusCode := int32(status)
	entry.ResponseStatus = &statusCode
	entry.ResponseBody = body
	now := time.Now()
	entry.CompletedAt = &now
	m.entries[memorySlot(userID, route, key)] = entry
	m.completed++
	return nil
}

func (m *memoryIdempotency) Abandon(_ context.Context, userID uuid.UUID, route, key string) error {
	delete(m.entries, memorySlot(userID, route, key))
	m.abandoned++
	return nil
}

func idempotentRequest(userID uuid.UUID, target, body, key string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Idempotency-Key", key)
	return r.Clone(WithUserID(r.Context(), userID))
}

func TestIdempotencyConflictIncludesRequestTarget(t *testing.T) {
	store := &memoryIdempotency{}
	calls := 0
	handler := NewIdempotency(store).Middleware("profile_issue")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls++
			WriteJSON(w, http.StatusCreated, map[string]string{"target": r.URL.RequestURI()})
		}))
	user, key := uuid.New(), "same-key"
	body := `{"server_id":"same-server"}`
	run := func(target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, idempotentRequest(user, target, body, key))
		return w
	}

	first := run("/api/v1/devices/device-a/profiles")
	replay := run("/api/v1/devices/device-a/profiles")
	otherDevice := run("/api/v1/devices/device-b/profiles")
	if first.Code != http.StatusCreated || replay.Code != http.StatusCreated ||
		replay.Header().Get("Idempotency-Replayed") != "true" || first.Body.String() != replay.Body.String() {
		t.Fatalf("повтор того же запроса: %d / %d, replayed=%q", first.Code, replay.Code,
			replay.Header().Get("Idempotency-Replayed"))
	}
	if otherDevice.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("другой путь с тем же ключом: код=%d, вызовов=%d; ожидался конфликт без вызова обработчика",
			otherDevice.Code, calls)
	}
}

func TestIdempotencyRetriesServerFailure(t *testing.T) {
	store := &memoryIdempotency{}
	calls := 0
	handler := NewIdempotency(store).Middleware("profile_issue")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				WriteError(w, r, http.StatusInternalServerError, ErrInternal, "зависимость недоступна", nil)
				return
			}
			WriteJSON(w, http.StatusCreated, map[string]int{"call": calls})
		}))
	user, key := uuid.New(), "retry-key"
	run := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, idempotentRequest(user, "/api/v1/devices/device-a/profiles", `{}`, key))
		return w
	}

	failed, retried, replay := run(), run(), run()
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("первый ответ = %d, ожидался 500", failed.Code)
	}
	if retried.Code != http.StatusCreated || replay.Code != http.StatusCreated || calls != 2 {
		t.Fatalf("повтор после 500: коды=%d/%d, вызовов=%d; ожидались 201/201 и два вызова",
			retried.Code, replay.Code, calls)
	}
	if retried.Body.String() != replay.Body.String() || store.abandoned != 1 || store.completed != 1 {
		t.Fatalf("слот после отказа: complete=%d, abandon=%d, тела=%s / %s",
			store.completed, store.abandoned, retried.Body, replay.Body)
	}
}

func TestIdempotencyReplaysImplicitOK(t *testing.T) {
	store := &memoryIdempotency{}
	calls := 0
	handler := NewIdempotency(store).Middleware("implicit_ok")(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			calls++
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
	user, key := uuid.New(), "implicit-key"
	run := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, idempotentRequest(user, "/api/v1/devices", `{}`, key))
		return w
	}
	first, replay := run(), run()
	if first.Code != http.StatusOK || replay.Code != http.StatusOK || calls != 1 ||
		first.Body.String() != replay.Body.String() {
		t.Fatalf("неявный 200: коды=%d/%d, вызовов=%d", first.Code, replay.Code, calls)
	}
}

//go:build integration

package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/httpx"
)

// seedIdemUser создаёт строку в users: idempotency_keys.user_id ссылается на
// users(id) (FK ON DELETE CASCADE), а случайный UUID без строки не прошёл бы.
// Имя отлично от seedUser задач 12+, чтобы не конфликтовать с будущим хелпером.
func seedIdemUser(t *testing.T, ctx context.Context, id uuid.UUID) {
	t.Helper()
	q := db.New(pool(t))
	if _, err := q.InsertUser(ctx, db.InsertUserParams{
		ID:           id,
		Email:        id.String() + "@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
		Locale:       "en",
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// mkIdempotency строит middleware поверх счётного обработчика: счётчик показывает,
// что повтор не дошёл до бизнес-логики.
func mkIdempotency(t *testing.T, calls *int) http.Handler {
	t.Helper()
	store := httpx.NewPGIdempotency(pool(t))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": "first-result", "call": *calls})
	})
	return httpx.NewIdempotency(store).Middleware("device_create")(h)
}

func withUser(r *http.Request, id uuid.UUID) *http.Request {
	return r.Clone(httpx.WithUserID(r.Context(), id))
}

func TestIdempotentReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	user, idemKey := uuid.New(), uuid.NewString()
	seedIdemUser(t, ctx, user)
	calls := 0
	h := mkIdempotency(t, &calls)
	body := []byte(`{"public_key":"wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iJ=","platform":"linux","name":"laptop"}`)

	run := func(payload []byte, withKey bool, u uuid.UUID) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(payload)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		if withKey {
			req.Header.Set("Idempotency-Key", idemKey)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withUser(req, u))
		return w
	}

	first, second := run(body, true, user), run(body, true, user)
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("statuses: %d / %d", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Errorf("replay body differs:\n  %s\n  %s", first.Body, second.Body)
	}
	if calls != 1 {
		t.Errorf("handler calls = %d, want 1", calls)
	}
	if !strings.Contains(second.Body.String(), `"call":1`) {
		t.Errorf("replay did not return the stored first result: %s", second.Body)
	}

	// Тот же ключ, другое тело → 409 idempotency_key_conflict.
	other := []byte(`{"public_key":"wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iK=","platform":"linux","name":"phone"}`)
	w := run(other, true, user)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"code":"idempotency_key_conflict"`) {
		t.Fatalf("conflict body = %d %s", w.Code, w.Body)
	}

	// Отсутствие обязательного ключа → 400 idempotency_key_required.
	w = run(other, false, user)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"idempotency_key_required"`) {
		t.Fatalf("missing key: %d %s", w.Code, w.Body)
	}

	// Другой пользователь с тем же ключом — не чужой результат (изолированный скоуп).
	user2 := uuid.New()
	seedIdemUser(t, ctx, user2)
	w = run(body, true, user2)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"call":2`) {
		t.Fatalf("same key, second user must run fresh: %d %s", w.Code, w.Body)
	}
}

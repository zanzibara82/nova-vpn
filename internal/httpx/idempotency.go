package httpx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

type IdempotencyStore interface {
	Claim(ctx context.Context, userID uuid.UUID, route, key string, hash []byte) (db.IdempotencyKey, bool, error)
	Complete(ctx context.Context, userID uuid.UUID, route, key string, status int, body []byte) error
	Abandon(ctx context.Context, userID uuid.UUID, route, key string) error
}

type Idempotency struct {
	store IdempotencyStore
}

func NewIdempotency(store IdempotencyStore) *Idempotency { return &Idempotency{store: store} }

// Middleware защищает критическую операцию (спецификация §5.2): повтор с тем же
// Idempotency-Key возвращает первый результат; конфликт тела — 409; незавершённый
// первый вызов — 409 in_progress, а не тихое ожидание.
func (i *Idempotency) Middleware(route string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := UserIDFromContext(r.Context())
			if !ok {
				// Middleware обязан стоять после аутентификации: без субъекта
				// ключ не имеет смысла (чужой ключ стал бы чужим результатом).
				WriteError(w, r, http.StatusUnauthorized, ErrUnauthenticated,
					"authentication required before idempotency", nil)
				return
			}
			key := r.Header.Get("Idempotency-Key")
			if key == "" || len(key) > 200 {
				WriteError(w, r, http.StatusBadRequest, ErrIdempotencyKeyRequired,
					"Idempotency-Key header is required for this operation", nil)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				WriteError(w, r, http.StatusBadRequest, ErrInvalidRequest, "cannot read body", nil)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			hash := sha256.Sum256(body)

			existing, found, err := i.store.Claim(r.Context(), userID, route, key, hash[:])
			if err != nil {
				WriteError(w, r, http.StatusInternalServerError, ErrInternal, "idempotency claim failed", nil)
				return
			}
			if found {
				if !bytes.Equal(existing.RequestHash, hash[:]) {
					WriteError(w, r, http.StatusConflict, ErrIdempotencyConflict,
						"Idempotency-Key was already used with a different request body", nil)
					return
				}
				if existing.CompletedAt == nil {
					WriteError(w, r, http.StatusConflict, ErrIdempotencyInProgress,
						"the first request with this key is still running", nil)
					return
				}
				// Повтор: отдать сохранённый результат, бизнес-логику не трогать.
				// ResponseStatus не nil: Complete пишет его вместе с completed_at.
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(int(*existing.ResponseStatus))
				_, _ = w.Write(existing.ResponseBody)
				return
			}

			rec := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				if rec.completed {
					_ = i.store.Complete(context.WithoutCancel(r.Context()), userID, route, key, rec.status, rec.body.Bytes())
				} else {
					// Отказ/паника: слот освобождается, чтобы клиент мог повторить.
					_ = i.store.Abandon(context.WithoutCancel(r.Context()), userID, route, key)
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

type captureWriter struct {
	http.ResponseWriter
	status    int
	body      bytes.Buffer
	completed bool
}

func (c *captureWriter) WriteHeader(status int) {
	c.status = status
	c.completed = status < 500
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	// Сохраняем тело для повтора и одновременно отдаём его клиенту.
	c.body.Write(p)
	c.completed = true
	return c.ResponseWriter.Write(p)
}

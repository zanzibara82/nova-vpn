package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorCode — стабильный контракт (спецификация §5.2). Переименование значения
// ломает клиентов, поэтому коды добавляются, а не правятся.
type ErrorCode string

const (
	ErrInvalidRequest         ErrorCode = "invalid_request"
	ErrUnauthenticated        ErrorCode = "unauthenticated"
	ErrAccountLocked          ErrorCode = "account_locked"
	ErrForbidden              ErrorCode = "forbidden"
	ErrNotFound               ErrorCode = "not_found"
	ErrConflict               ErrorCode = "conflict"
	ErrDeviceLimitReached     ErrorCode = "device_limit_reached"
	ErrDuplicateDevice        ErrorCode = "duplicate_device"
	ErrIdempotencyKeyRequired ErrorCode = "idempotency_key_required"
	ErrIdempotencyConflict    ErrorCode = "idempotency_key_conflict"
	ErrIdempotencyInProgress  ErrorCode = "idempotency_key_in_progress"
	ErrRateLimited            ErrorCode = "rate_limited"
	ErrInternal               ErrorCode = "internal"
)

type errorBody struct {
	Code      ErrorCode      `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id"`
}

type envelope struct {
	Error errorBody `json:"error"`
}

// WriteError пишет тело в документированном формате и никогда не пишет секретные
// детали: message — человекочитаемое объяснение, details — только коды и лимиты.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code ErrorCode, message string, details map[string]any) {
	id := ""
	if r != nil {
		id = RequestIDFromContext(r.Context())
	}
	if id == "" {
		// Случай без middleware (тесты, внутренние вызовы): request_id обязан
		// существовать всегда, иначе лог и тело не сопоставить.
		id = newRequestID()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Request-Id", id)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(envelope{Error: errorBody{
		Code: code, Message: message, Details: details, RequestID: id,
	}}); err != nil {
		slog.Error("httpx: error write failed", "err", err, "request_id", id)
	}
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand отказывает только при сломанном системном entropy;
		// падать из-за этого в обработчике ошибок нельзя.
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

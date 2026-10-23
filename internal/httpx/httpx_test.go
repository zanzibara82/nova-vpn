package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestErrorEnvelopeShape(t *testing.T) {
	var captured string
	handler := NewRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = RequestIDFromContext(r.Context())
		WriteError(w, r, http.StatusConflict, ErrDeviceLimitReached, "device limit reached",
			map[string]any{"limit": 3})
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	var got struct {
		Error struct {
			Code      string         `json:"code"`
			Message   string         `json:"message"`
			Details   map[string]any `json:"details"`
			RequestID string         `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not the documented envelope: %v (%s)", err, w.Body)
	}
	if got.Error.Code != "device_limit_reached" || got.Error.Message == "" {
		t.Errorf("bad code/message: %+v", got.Error)
	}
	if got.Error.RequestID == "" || got.Error.RequestID != captured {
		t.Errorf("request_id in body %q must equal middleware value %q", got.Error.RequestID, captured)
	}
	if w.Header().Get("X-Request-Id") != captured {
		t.Errorf("X-Request-Id header %q != body %q", w.Header().Get("X-Request-Id"), captured)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(captured) {
		t.Errorf("request id %q is not 16 lowercase hex chars", captured)
	}
}

func TestErrorEnvelopeWithoutRequestContext(t *testing.T) {
	// Вызовы WriteError без контекста (например, из юнита или из сборщика ошибок)
	// не должны ронять сервер и не должны рисовать пустой request_id,
	// как будто он существует.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	WriteError(w, r, http.StatusInternalServerError, ErrInternal, "boom", nil)
	if !regexp.MustCompile(`"request_id":"[0-9a-f]{16}"`).MatchString(w.Body.String()) {
		t.Fatalf("missing synthesized request_id: %s", w.Body)
	}
}

func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
	body := "[" + repeatX("a", 5000) + "]"
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	var dst struct{ A string }
	if err := DecodeJSON(r, &dst, 64); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func repeatX(s string, n int) string { return strings.Repeat(s, n) }

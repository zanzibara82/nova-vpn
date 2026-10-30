package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// whoamiTest — вызов обработчика без открытия порта: порт здесь не нужен, потому что
// проверяется разбор RemoteAddr и форма ответа, а не сеть.
func whoamiTest(t *testing.T, remote string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.RemoteAddr = remote
	for name, values := range header {
		req.Header[name] = values
	}
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)
	return rec
}

func TestWhoamiReturnsIPv4RemoteHost(t *testing.T) {
	rec := whoamiTest(t, "172.31.98.2:51820", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код ответа %d, ожидался 200", rec.Code)
	}
	if got := rec.Body.String(); got != "172.31.98.2\n" {
		t.Fatalf("тело %q, ожидалось %q", got, "172.31.98.2\n")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("тип ответа %q, ожидался text/plain; charset=utf-8", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control %q, ожидался no-store", got)
	}
}

func TestWhoamiReturnsIPv6RemoteHost(t *testing.T) {
	rec := whoamiTest(t, "[2001:db8::7]:443", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код ответа %d, ожидался 200", rec.Code)
	}
	if got := rec.Body.String(); got != "2001:db8::7\n" {
		t.Fatalf("тело %q, ожидалось %q", got, "2001:db8::7\n")
	}
}

func TestWhoamiRejectsMalformedRemoteAddr(t *testing.T) {
	rec := whoamiTest(t, "без-порта", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("код ответа %d, ожидался 500", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) == "" {
		t.Fatal("на неверный RemoteAddr пустое тело ошибки")
	}
}

// Заголовок не должен подменять источник адреса: именно адрес из RemoteAddr
// доказывает, откуда пришёл пакет, а X-Forwarded-For клиент пишет сам.
func TestWhoamiIgnoresForwardedHeader(t *testing.T) {
	rec := whoamiTest(t, "10.99.7.2:41234", http.Header{"X-Forwarded-For": []string{"203.0.113.9"}})
	if got := rec.Body.String(); got != "10.99.7.2\n" {
		t.Fatalf("тело %q, ожидался адрес из RemoteAddr", got)
	}
}

func TestHealthzIsPlainOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("код ответа %d, ожидался 200", rec.Code)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Fatalf("тело %q, ожидалось %q", got, "ok\n")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("тип ответа %q, ожидался text/plain; charset=utf-8", got)
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код ответа %d, ожидался 404", rec.Code)
	}
}

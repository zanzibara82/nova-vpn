// Package nodeapi — HTTP-контракт управляющего API со стороны vpn-узла
// (/internal/v1). Узел не пользователь: у него нет JWT, нет планов и нет права
// что-либо менять в чужом наборе, поэтому аутентификация, сверка пути с токеном и
// лимит здесь свои (спецификация §4.1, §5.2).
package nodeapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/httpx"
	"github.com/novavpn/novavpn/internal/servers"
	"github.com/novavpn/novavpn/internal/telemetry"
)

const (
	// enrollMaxBody — enroll ровно из двух строк; мегабайт это уже атака размером.
	enrollMaxBody = 1 << 20
	// reportMaxBody — потолок тела отчёта. Он обязан быть выше законного отчёта:
	// MaxReportPeers пиеров это примерно 0,4 MiB, и порог «на глаз» отрезал бы
	// настоящий отчёт большого узла, оставляя лимит только на память процесс
	// вместо отказа по числу пиеров.
	reportMaxBody = 4 << 20
)

type Handler struct {
	q    *db.Queries
	tel  *telemetry.Service
	auth *Authenticator
	log  *slog.Logger
}

func NewHandler(q *db.Queries, tel *telemetry.Service, log *slog.Logger) *Handler {
	return &Handler{q: q, tel: tel, auth: NewAuthenticator(q, log), log: log}
}

// NodeMiddleware — обёртка dec.Node для сборщика. Один Authenticator на весь
// префикс: у маршрутов и проверки общий источник правды (q), а два экземпляра
// означали бы две реализации одного правила.
func (h *Handler) NodeMiddleware() func(http.Handler) http.Handler {
	return h.auth.Middleware
}

// RegisterRoutes монтирует контракт узла.
//
// enroll — единственный маршрут префикса без узлового токена: у ещё не
// зарегистрированного узла токена нет физически. Он идёт под dec.Anonymous (бакет
// по IP), потому что ключ бакета «на узел» для него взять неоткуда.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	mux.Handle("POST /internal/v1/nodes/enroll", dec.Anonymous(http.HandlerFunc(h.enroll)))
	mux.Handle("GET /internal/v1/nodes/{server_id}/desired", dec.Node(http.HandlerFunc(h.desired)))
	mux.Handle("POST /internal/v1/nodes/{server_id}/observed", dec.Node(http.HandlerFunc(h.observed)))
	mux.Handle("POST /internal/v1/nodes/{server_id}/heartbeat", dec.Node(http.HandlerFunc(h.heartbeat)))
	mux.Handle("POST /internal/v1/nodes/{server_id}/token/rotate", dec.Node(http.HandlerFunc(h.rotate)))
}

// pathServer сверяет id узла из пути с id, который дал токен, и возвращает
// предъявленные полномочия.
//
// Порядок проверок значим дважды. Не-UUID — дефект запроса (400), а валидный
// чужой id — отказ по правам (403): по коду узел понимает, что его токен принят, и
// это не оракул, потому что свой токен он знает сам. Несуществующий сервер в пути
// остаётся 403: «такого узла нет» и «это не твой узел» различать нечем и незачем.
func (h *Handler) pathServer(w http.ResponseWriter, r *http.Request) (credential, bool) {
	pathID, err := uuid.Parse(r.PathValue("server_id"))
	if err != nil {
		h.badField(w, r, "server_id", "server_id в пути должен быть uuid")
		return credential{}, false
	}
	cred, ok := credentialFromContext(r.Context())
	if !ok || cred.serverID != pathID {
		h.log.Warn("node route refused", "reason", "server_mismatch", "path_server_id", pathID)
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrForbidden, "несовпадение сервера", nil)
		return credential{}, false
	}
	return cred, true
}

// desired отдаёт набор пиеров узла.
//
// ETag — сильный валидатор от содержимого набора, а не от config_version. Версия
// поднимается явными действиями (выдача, отзыв, ротация), но набор меняется ещё и
// сам: overlap-окно закрывается по времени, а старый ключ снимается сразу после
// handshake нового (§7.3). С версионным ETag узел получал бы 304 и держал снятый
// ключ до следующего явного изменения. measured_at из хэша исключён: это время
// ответа, а не содержимое, и с ним 304 не случился бы никогда.
func (h *Handler) desired(w http.ResponseWriter, r *http.Request) {
	cred, ok := h.pathServer(w, r)
	if !ok {
		return
	}
	set, err := servers.Compute(r.Context(), h.q, cred.serverID, time.Now().UTC())
	if errors.Is(err, servers.ErrServerUnknown) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrNotFound, "сервер не найден", nil)
		return
	}
	if err != nil {
		h.internal(w, r, err, "desired set compute")
		return
	}
	etag, err := desiredETag(set)
	if err != nil {
		h.internal(w, r, err, "desired set etag")
		return
	}
	w.Header().Set("ETag", etag)
	// Сравнение строгое: слабый валидатор (W/) и префиксы поддержкой не считаются,
	// а «примерно совпало» для узла означает пропущенное отсечение пиера.
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_ = httpx.WriteJSON(w, http.StatusOK, set)
}

// desiredETag — хэш содержимого набора. Поля DesiredSet и Peer имеют фиксированный
// порядок, пиры отсортированы, поэтому один и тот же набор даёт один и тот же хэш.
func desiredETag(set servers.DesiredSet) (string, error) {
	set.MeasuredAt = time.Time{}
	body, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("nodeapi: сериализация desired set: %w", err)
	}
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`, nil
}

func (h *Handler) observed(w http.ResponseWriter, r *http.Request) {
	cred, ok := h.pathServer(w, r)
	if !ok {
		return
	}
	var rep telemetry.ObservedReport
	if !h.decode(w, r, &rep, reportMaxBody) {
		return
	}
	if err := h.tel.IngestObserved(r.Context(), cred.serverID, rep, time.Now().UTC()); err != nil {
		h.reportRefused(w, r, err, "observed")
		return
	}
	h.noContent(w)
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	cred, ok := h.pathServer(w, r)
	if !ok {
		return
	}
	var hb telemetry.Heartbeat
	if !h.decode(w, r, &hb, reportMaxBody) {
		return
	}
	if err := h.tel.IngestHeartbeat(r.Context(), cred.serverID, hb, time.Now().UTC()); err != nil {
		h.reportRefused(w, r, err, "heartbeat")
		return
	}
	h.noContent(w)
}

// rotate перевыпускает узловой токен, предъявленный этим же запросом.
//
// Порядок «вставил новый, потом отзывать старый» обязателен: обратный оставил бы
// узел без доступа при ошибке вставки, то есть одна опечатка в генераторе
// выключала бы vpn-сервер. Цена размена известна: узел, потерявший ответ, уходит в
// enroll заново, а при ошибке отзыва оба токена живут (случай пишется в журнал).
func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	cred, ok := h.pathServer(w, r)
	if !ok {
		return
	}
	token, err := newNodeToken()
	if err != nil {
		h.internal(w, r, err, "node token generation")
		return
	}
	if _, err := h.q.InsertNodeCredential(r.Context(), db.InsertNodeCredentialParams{
		ID: uuid.New(), ServerID: cred.serverID, TokenHash: hashToken(token), RotatedFrom: &cred.id,
	}); err != nil {
		h.internal(w, r, err, "rotated node credential insert")
		return
	}
	revoked, err := h.q.RevokeNodeCredential(r.Context(), cred.id)
	if err != nil {
		h.log.Error("node credential revoke after rotation failed", "error", err, "server_id", cred.serverID)
	} else if revoked == 0 {
		h.log.Warn("node credential already revoked", "server_id", cred.serverID)
	}
	h.log.Info("node token rotated", "server_id", cred.serverID)
	_ = httpx.WriteJSON(w, http.StatusOK, NodeTokenResponse{ServerID: cred.serverID.String(), NodeToken: token})
}

// reportRefused — единый выход для «отчёт не принят». Ошибка валидации это дефект
// запроса (400), прочее — наша поломка (500): узел по коду решает, переотправлять
// то же тело или бить тревогу, поэтому подменять одно другим нельзя.
func (h *Handler) reportRefused(w http.ResponseWriter, r *http.Request, err error, what string) {
	if errors.Is(err, telemetry.ErrInvalidReport) {
		h.log.Warn("node report refused", "reason", "invalid_report", "report", what)
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"отчёт не соответствует контракту", nil)
		return
	}
	h.internal(w, r, err, what+" ingest")
}

func (h *Handler) noContent(w http.ResponseWriter) {
	// 204 без тела: ответ отчёта не содержит ничего, чего узел не знал бы сам,
	// а Content-Type на 204 противоречил бы RFC 9110.
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	if err := httpx.DecodeJSON(r, dst, maxBytes); err != nil {
		h.log.Warn("node request body refused", "error", err)
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"тело должно быть одним JSON-объектом с полями из документации", nil)
		return false
	}
	return true
}

func (h *Handler) badField(w http.ResponseWriter, r *http.Request, field, message string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
		message, map[string]any{"field": field})
}

func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, reason string, serverID uuid.UUID) {
	if serverID == uuid.Nil {
		h.log.Warn("node enroll refused", "reason", reason)
	} else {
		h.log.Warn("node enroll refused", "reason", reason, "server_id", serverID)
	}
	// Один текст на все причины: «не знаем такого», «просрочен», «израсходован»,
	// «отозван», «ключ не тот» и «сервер удалён» различаются только в журнале.
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "стартовый токен не принят", nil)
}

func (h *Handler) internal(w http.ResponseWriter, r *http.Request, err error, what string) {
	h.log.Error("nodeapi: "+what+" failed", "error", err)
	httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "внутренняя ошибка", nil)
}

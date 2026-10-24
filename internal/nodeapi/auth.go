package nodeapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/httpx"
)

// deniedMessage — единственный текст отказа узла. «Не знаем такого», «отозван» и
// «битый формат» наружу неразличимы: для узла-самозванца эта разница была бы
// оракулом «мой токен хотя бы зарегистрирован» (§2).
const deniedMessage = "требуется токен узла"

// credential — предъявленные полномочия: id строки node_credentials и её сервер.
// id нужен ротации (отзывать ровно то, чем подписали запрос, а не «самый свежий
// токен узла»), а сервер нужен каждому маршруту префикса.
type credential struct {
	id       uuid.UUID
	serverID uuid.UUID
}

type credentialKey struct{}

func contextWithCredential(ctx context.Context, c credential) context.Context {
	return context.WithValue(ctx, credentialKey{}, c)
}

func credentialFromContext(ctx context.Context) (credential, bool) {
	c, ok := ctx.Value(credentialKey{}).(credential)
	return c, ok
}

// Authenticator проверяет узловой токен и кладёт субъекта в контекст.
//
// Кэша нет сознательно: узловой токен бессрочен до отзыва и ротации, поэтому
// «примерно последний известный набор» означал бы, что отзыв (задача 12) или
// ротация вступают в силу через неопределённое время.
type Authenticator struct {
	q   *db.Queries
	log *slog.Logger
}

func NewAuthenticator(q *db.Queries, log *slog.Logger) *Authenticator {
	return &Authenticator{q: q, log: log}
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := auth.Bearer(r)
		if token == "" {
			a.deny(w, r, "missing")
			return
		}
		sum := sha256.Sum256([]byte(token))
		cred, err := a.q.NodeCredentialByHash(r.Context(), sum[:])
		if errors.Is(err, pgx.ErrNoRows) {
			// «Битый формат» — сюда же: ни длина, ни алфавит предъявленной строки в
			// журнал не пишутся, иначе строка журнала становится словаром токенов.
			a.deny(w, r, "unknown")
			return
		}
		if err != nil {
			a.internal(w, r, err, "node credential lookup")
			return
		}
		// Одна запись на запрос: last_used_at — доказательство жизни, без него
		// отзыв «неиспользуемого» токена слеп.
		if err := a.q.TouchNodeCredential(r.Context(), cred.ID); err != nil {
			a.internal(w, r, err, "node credential touch")
			return
		}
		ctx := httpx.WithServerID(r.Context(), cred.ServerID)
		ctx = contextWithCredential(ctx, credential{id: cred.ID, serverID: cred.ServerID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) deny(w http.ResponseWriter, r *http.Request, reason string) {
	a.log.Warn("node token refused", "reason", reason)
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, deniedMessage, nil)
}

func (a *Authenticator) internal(w http.ResponseWriter, r *http.Request, err error, what string) {
	// Текст ошибки БД наружу не уходит: он описывает схему и столбцы (§11).
	a.log.Error("nodeapi: "+what+" failed", "error", err)
	httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "внутренняя ошибка", nil)
}

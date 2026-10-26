package nodeapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/httpx"
)

// EnrollRequest — тело POST /internal/v1/nodes/enroll. Поля обязательны: без
// стартового токена enroll не имеет смысла, а без ключа нечем проверить, что
// регистрируется именно тот узел, которому токен выдавали.
type EnrollRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	PublicKey      string `json:"public_key"`
}

// NodeTokenResponse — ответ enroll и ротации. Узловой токен отдаётся ровно один
// раз: в БД лежит только sha256, поэтому ни повтор запроса, ни журнал, ни админский
// список («какой у узла токен») его не восстановят.
type NodeTokenResponse struct {
	ServerID  string `json:"server_id"`
	NodeToken string `json:"node_token"`
}

// nodeTokenBytes — 32 байта: столько же, сколько entropy у ключа curve25519, и
// ровно столько, сколько требует CHECK octet_length = 32 на token_hash-подобных
// колонках. base64url без дополнений из 32 байт — 43 символа.
const nodeTokenBytes = 32

// errEnrollRace — условие used_at IS NULL в ConsumeBootstrapToken не нашло строку:
// одноразовый токен выиграл параллельный enroll. Отдельная ошибка нужна, чтобы
// отличить гонку (401 без оракула) от настоящего отказа БД (500).
var errEnrollRace = errors.New("nodeapi: bootstrap token race")

func newNodeToken() (string, error) {
	var b [nodeTokenBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand отказывает только при сломанном системном entropy. Молча
		// вернуться к math/rand значило бы выдать узлу предсказуемый секрет.
		return "", fmt.Errorf("nodeapi: node token entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashToken(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// enroll регистрирует узел по одноразовому стартовому токену.
//
// Порядок проверок задан тем, что из отказа нельзя сделать оракул: сначала
// дефекты запроса (400, секрет ещё не потрачен), потом сверка токена и ключа
// (401, токен не потрачен), и только потом расходование (ConsumeBootstrapToken).
// Опечатка в public_key поэтому не сжигает стартовый токен: админ не обязан
// перевыпускать его из-за одной опечатки.
func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	var in EnrollRequest
	if !h.decode(w, r, &in, enrollMaxBody) {
		return
	}
	if in.BootstrapToken == "" {
		h.badField(w, r, "bootstrap_token", "bootstrap_token обязателен")
		return
	}
	if _, err := devices.ParsePublicKey(in.PublicKey); err != nil {
		// Каноничность проверяется тем же ParsePublicKey, что и ключи устройств
		// (задача 14 A-1): второй реализация «что такое ключ» неизбежно разъехалась бы.
		h.badField(w, r, "public_key", "нужен канонический публичный ключ WireGuard")
		return
	}

	now := time.Now().UTC()
	bt, err := h.q.BootstrapTokenByHash(r.Context(), hashToken(in.BootstrapToken))
	if errors.Is(err, pgx.ErrNoRows) {
		h.refuse(w, r, "unknown", uuid.Nil)
		return
	}
	if err != nil {
		h.internal(w, r, err, "bootstrap token lookup")
		return
	}
	switch {
	case bt.UsedAt != nil:
		h.refuse(w, r, "used", bt.ServerID)
		return
	case bt.RevokedAt != nil:
		h.refuse(w, r, "revoked", bt.ServerID)
		return
	case !bt.ExpiresAt.After(now):
		h.refuse(w, r, "expired", bt.ServerID)
		return
	}

	srv, err := h.q.ServerByID(r.Context(), bt.ServerID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Токен годный, а сервера нет — испорченная операция админа: удаление
		// узла без отзыва его токена. Узлу это говорит ровно одно: «перерегистрируйся»,
		// поэтому ответ тот же 401, а оператор получает сигнал в журнале.
		h.log.Error("bootstrap token refers to a missing server", "server_id", bt.ServerID)
		h.refuse(w, r, "server_missing", bt.ServerID)
		return
	}
	if err != nil {
		h.internal(w, r, err, "server lookup during enroll")
		return
	}
	if srv.PublicKey != in.PublicKey {
		// Ключ неканонических форм уже не бывает (см. ParsePublicKey), поэтому
		// сравнение строк — сравнение ключей, а не сравнение их записей.
		h.refuse(w, r, "key_mismatch", bt.ServerID)
		return
	}

	// Токен генерируется до расхода стартового: отказ crypto/rand не имеет права
	// сжечь одноразовый токен.
	token, err := newNodeToken()
	if err != nil {
		h.internal(w, r, err, "node token generation")
		return
	}
	// Расход, отзыв прежних и вставка нового — одна транзакция. По отдельности отказ
	// вставки оставлял бы сожжённый стартовый токен и уже отозванный рабочий:
	// перерегистрация невозможна ни старым токеном, ни новым.
	var owner uuid.UUID
	err = db.RunInTx(r.Context(), h.pool, func(q *db.Queries) error {
		var err error
		owner, err = q.ConsumeBootstrapToken(r.Context(), bt.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return errEnrollRace
		}
		if err != nil {
			return err
		}
		// Прежние токены гасятся до вставки: украденный старый не имеет права жить
		// рядом с новым, а узел в этом месте всё равно перерегистрируется.
		if _, err := q.RevokeNodeCredentialsForServer(r.Context(), owner); err != nil {
			return err
		}
		_, err = q.InsertNodeCredential(r.Context(), db.InsertNodeCredentialParams{
			ID: uuid.New(), ServerID: owner, TokenHash: hashToken(token),
		})
		return err
	})
	if errors.Is(err, errEnrollRace) {
		// Условие used_at IS NULL в том же UPDATE: выиграл один из параллельных enroll.
		h.refuse(w, r, "race", bt.ServerID)
		return
	}
	if err != nil {
		h.internal(w, r, err, "enroll transaction")
		return
	}
	h.log.Info("node enrolled", "server_id", owner)
	// 200, а не 201: узел не создаёт объект от имени пользователя, он получает
	// пропуск к уже зарегистрированной за собой строке.
	_ = httpx.WriteJSON(w, http.StatusOK, NodeTokenResponse{ServerID: owner.String(), NodeToken: token})
}

//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

// captured — один прогнанный запрос с сырым ответом. Тело не распаковывается в
// словари: проверка секрета по строке обязана видеть ровно те байты, что ушли
// клиенту, включая те, что не влезли бы в map.
type captured struct {
	method, path string
	status       int
	body         []byte
}

// secret — значение, которое не имеет права оказаться в чужом ответе или в журнале.
// allow — единственные пути, где оно законно (так session-ответ имеет право содержать
// выданный им токен, а журнал — не имеет никогда).
type secret struct {
	label string
	value string
	allow []string
}

type evidence struct {
	calls   []captured
	secrets []secret
}

func (ev *evidence) addSecret(label, value string, allow ...string) {
	ev.secrets = append(ev.secrets, secret{label: label, value: value, allow: allow})
}

// env — собранный роутер (тот же, что в задаче 18) плюс способ получать состояния
// аккаунта, не дёргая публичные маршруты лишний раз.
type env struct {
	srv  *httptest.Server
	log  *bytes.Buffer
	q    *db.Queries
	sess *auth.SessionService
	ev   *evidence
}

// seedPassword — пароль, который кладёт в users хелпер seedUser (задача 12). Он не
// testPassword, и матрица обязана это различать: login по seed-аккаунту с testPassword
// был бы 401, и проверка «верный пароль» ничего не проверяла бы.
const seedPassword = "integration-password-123"

func newEnv(t *testing.T) *env {
	t.Helper()
	srv, buf := newRouter(t)
	q := db.New(pool(t))
	iss := auth.NewIssuer(bytes32ForTests(), 10*time.Minute)
	// Denylist этому сервису не нужен (nil): здесь он только выпускает сессии, а
	// NewSession его не читает. Отзыв семей идёт через сам HTTP, где denylist стоит в
	// роутере на девятой базе Redis; свой клиент с нулевой базы приплёл бы в тест
	// состояние, которого в проде нет.
	sess := auth.NewSessionService(q, iss, nil, 24*time.Hour, discardLog())
	// srv.Close уже зарегистрирован в newRouter (задача 18) — второй cleanup не нужен.
	e := &env{srv: srv, log: buf, q: q, sess: sess, ev: &evidence{}}
	e.ev.addSecret("test password", testPassword)
	e.ev.addSecret("seed password", seedPassword)
	return e
}

type actor struct {
	userID  uuid.UUID
	email   string
	access  string
	refresh string
}

// mint — состояние «пользователь есть в базе, подписка активна» без единого
// HTTP-запроса: seedUser создаёт аккаунт с подпиской internal-default, NewSession
// выпускает ему живую пару токенов. Ip = nil: колонка nullable, и анти-фрод-столбец
// проверяется в задаче 12, не здесь.
func (e *env) mint(t *testing.T) actor {
	t.Helper()
	ctx := context.Background()
	id := seedUserWithPlan(t, ctx, e.q, "internal-default")
	s, err := e.sess.NewSession(ctx, id, nil)
	if err != nil {
		t.Fatalf("NewSession(%s): %v", id, err)
	}
	u, err := e.q.UserByID(ctx, id)
	if err != nil {
		t.Fatalf("UserByID(%s): %v", id, err)
	}
	e.ev.addSecret("access/"+id.String()[:8], s.AccessToken, issuePaths...)
	e.ev.addSecret("refresh/"+id.String()[:8], s.RefreshToken, issuePaths...)
	return actor{userID: id, email: u.Email, access: s.AccessToken, refresh: s.RefreshToken}
}

// issuePaths — единственные маршруты, ответ которых имеет право содержать выданный
// токен. Всё остальное (журнал, чужой ответ, 4xx-конверт) содержать токен не должно.
var issuePaths = []string{
	"/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh",
}

// lapse — подписка закончилась час назад: права на устройства нет, но аккаунт
// по-прежнему описывается /me. Оба поля меняются вместе, иначе падает CHECK
// subscriptions_window (ends_at > starts_at): seedUser вставляет starts_at = now(), и
// «now() − 1 час» оказался бы раньше собственного начала.
func (e *env) lapse(t *testing.T, a actor) actor {
	t.Helper()
	_, err := pool(t).Exec(context.Background(),
		`UPDATE subscriptions
		    SET starts_at = now() - interval '3 hours',
		        ends_at   = now() - interval '1 hour'
		  WHERE user_id = $1`, a.userID)
	if err != nil {
		t.Fatalf("lapse: %v", err)
	}
	return a
}

// block — статус locked. Причина обязательна (CHECK users_lock_reason), а её Go-форма
// зависит от того, как sqlc разметил nullable-параметр: здесь *string, как у всех
// nullable-параметров этого плана при emit_pointers_for_null_types (ср. DisplayName в
// InsertUserParams). Если сгенерирован скаляр — правь это место и оба вызова LockUser в
// задаче 17 тем же коммитом: в одном пакете две формы не компилируются.
func (e *env) block(t *testing.T, a actor) actor {
	t.Helper()
	reason := "acceptance-matrix"
	if err := e.q.LockUser(context.Background(), db.LockUserParams{
		ID: a.userID, LockedReason: &reason,
	}); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	return a
}

// register — участник, заведённый через сам API: этот путь обязан работать end-to-end,
// и только ради него матрица тратит анонимный bucket.
func (e *env) register(t *testing.T) actor {
	t.Helper()
	email := "matrix-" + uuid.NewString()[:8] + "@novavpn.test"
	resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/register",
		map[string]string{"email": email, "password": testPassword}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("register body: %v (%s)", err, body)
	}
	s := decodeSession(t, out)
	e.ev.addSecret("access/register", s.AccessToken, issuePaths...)
	e.ev.addSecret("refresh/register", s.RefreshToken, issuePaths...)
	e.ev.addSecret("email/register", email, "/api/v1/me")
	// ID участника берём из /me: ответ регистрации id не содержит (контракт — Session),
	// и это тоже проверка — /me по выданному токену обязан пускать.
	resp, body = raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(s.AccessToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me after register = %d %s", resp.StatusCode, body)
	}
	var me struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("me body: %v (%s)", err, body)
	}
	return actor{userID: uuid.MustParse(me.User.ID), email: email,
		access: s.AccessToken, refresh: s.RefreshToken}
}

// raw — то же, что do (задача 17), но с произвольными заголовками и сырым телом:
// сверка с контрактом идёт по байтам ответа, а не по уже распакованной карте.
// Каждый вызов попадает в evidence — и успешный, и провальный.
func raw(t *testing.T, e *env, method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = jsonBody(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	e.ev.calls = append(e.ev.calls, captured{
		method: method, path: path, status: resp.StatusCode, body: data,
	})
	return resp, data
}

// codeOf разбирает конверт и возвращает error.code; для пустого тела (204) — "".
func codeOf(t *testing.T, body []byte) string {
	t.Helper()
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("not an envelope: %v (%s)", err, body)
	}
	return v.Error.Code
}

// codeAndMessage — пара «code|message» из байт ответа, без request_id. Нужна ровно для
// одного: сравнить два отказа как «одинаковый ответ», не сравнив при этом случайное.
// Map-версия этого лежит в задаче 17 (envelopePair); здесь тело ещё не распаковано, и
// вторая функция дешевле, чем переписывать helper на байты.
func codeAndMessage(t *testing.T, body []byte) string {
	t.Helper()
	var v struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("not an envelope: %v (%s)", err, body)
	}
	return v.Error.Code + "|" + v.Error.Message
}

type routeCase struct {
	name string
	want int
	code string // "" — успешный ответ, тела-конверта нет
	run  func(t *testing.T, e *env) int
}

// Матрица. Строки сгруппированы по маршруту, чтобы читалось как таблица, а не как
// пересказ тестов задач 15–18. Числа в want/code — не «как удобно», а как обещано в
// api-spec/openapi.yaml; расхождение ловит Step 3, а не этот список.
func matrixCases() []routeCase {
	return []routeCase{
		{"GET /devices аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, nil)
			return resp.StatusCode
		}},
		{"GET /devices участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices без подписки", http.StatusOK, "", func(t *testing.T, e *env) int {
			// Список устройств — не право на новую выдачу: он остаётся доступен,
			// иначе человек не сможет посмотреть, что у него было.
			a := e.lapse(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices заблокированный (токен выдан до блокировки)", http.StatusOK, "", func(t *testing.T, e *env) int {
			// Замеренное ограничение, а не ошибка: middleware проверяет подпись, срок
			// и denylist, статус пользователя он не перечитывает. Окно = AccessTTL
			// (10 минут); срочный отзыв access — только denylist при logout.
			// Спецификация §13.11 это описывает, и описывает именно так.
			a := e.block(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"POST /devices аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(1), "platform": "linux", "name": "d"},
				idem())
			return resp.StatusCode
		}},
		{"POST /devices участник", http.StatusCreated, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(11), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices второй раз тем же ключом", http.StatusConflict, "duplicate_device", func(t *testing.T, e *env) int {
			a := e.mint(t)
			raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(12), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(12), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices тот же Idempotency-Key, другое тело", http.StatusConflict, "idempotency_key_conflict", func(t *testing.T, e *env) int {
			a := e.mint(t)
			key := newIdem()
			raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(13), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idemWith(key)))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(14), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idemWith(key)))
			return resp.StatusCode
		}},
		{"POST /devices без Idempotency-Key", http.StatusBadRequest, "idempotency_key_required", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(15), "platform": "linux", "name": "d"},
				authHdr(a.access))
			return resp.StatusCode
		}},
		{"POST /devices некорректный public_key", http.StatusBadRequest, "invalid_request", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": "not-a-key", "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices без подписки", http.StatusForbidden, "forbidden", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(16), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"GET /me участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /me без подписки (plan null, limit 0)", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			resp, body := raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(a.access))
			var me struct {
				Plan    *json.RawMessage `json:"plan"`
				Devices struct {
					Limit int `json:"limit"`
				} `json:"devices"`
			}
			if err := json.Unmarshal(body, &me); err != nil {
				t.Fatalf("me body: %v (%s)", err, body)
			}
			if me.Plan != nil {
				t.Errorf("lapsed plan must be null, got %s", *me.Plan)
			}
			if me.Devices.Limit != 0 {
				t.Errorf("lapsed limit = %d, want 0 (права на устройства нет)", me.Devices.Limit)
			}
			return resp.StatusCode
		}},
		{"GET /me аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, nil)
			return resp.StatusCode
		}},
		{"GET /me произвольной подписью", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			// Подпись HS256 проверяется на секрет сервера: «Bearer» со случайной
			// строкой — это 401, а не 500 и не «пустой субъект».
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil,
				map[string]string{"Authorization": "Bearer " + strings.Repeat("x", 64)})
			return resp.StatusCode
		}},
		{"POST /login правильный пароль", http.StatusOK, "", func(t *testing.T, e *env) int {
			// seed-аккаунт, а не register: этот случай ничего не должен анонимному
			// bucket'у register и берёт ровно один свой вызов.
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return resp.StatusCode
		}},
		{"POST /login неверный пароль", http.StatusUnauthorized, "invalid_credentials", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": "wrong-password-123"}, nil)
			return resp.StatusCode
		}},
		{"POST /login несуществующий адрес неотличим", http.StatusUnauthorized, "invalid_credentials", func(t *testing.T, e *env) int {
			// Целевой вызов — этот, сравнение берёт предыдущий (неверный пароль).
			// Различаются код и сообщение; request_id различаться обязан, поэтому в
			// сравнение не входит.
			resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": "ghost-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": seedPassword}, nil)
			prev := e.ev.calls[len(e.ev.calls)-2].body
			if codeAndMessage(t, prev) != codeAndMessage(t, body) {
				t.Errorf("unknown email differs from wrong password: %s vs %s", body, prev)
			}
			return resp.StatusCode
		}},
		{"POST /login заблокированного", http.StatusForbidden, "account_locked", func(t *testing.T, e *env) int {
			// Пароль верный: ответ «заблокирован» выдаётся только после проверки пароля
			// (задача 17), иначе сама блокировка стала бы оракулом существования адреса.
			a := e.block(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return resp.StatusCode
		}},
		{"POST /register повтор адреса", http.StatusConflict, "email_taken", func(t *testing.T, e *env) int {
			a := e.register(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": a.email, "password": testPassword}, nil)
			return resp.StatusCode
		}},
		{"POST /register слабый пароль", http.StatusBadRequest, "invalid_request", func(t *testing.T, e *env) int {
			resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": "weak-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": "short"}, nil)
			// Поле в details обязательно: без него клиент получает «что-то не так» и
			// угадывает, какое из двух полей портить.
			var v struct {
				Error struct {
					Details map[string]any `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(body, &v); err != nil {
				t.Fatalf("register 400 body: %v (%s)", err, body)
			}
			if v.Error.Details["field"] != "password" {
				t.Errorf("details = %v, want field=password", v.Error.Details)
			}
			return resp.StatusCode
		}},
		{"POST /refresh действующим", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			var out map[string]any
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("refresh body: %v (%s)", err, body)
			}
			s := decodeSession(t, out)
			e.ev.addSecret("access/refreshed", s.AccessToken, issuePaths...)
			e.ev.addSecret("refresh/refreshed", s.RefreshToken, issuePaths...)
			// Переиспользование старого refresh здесь не проверяется: оно проверено
			// через HTTP в auth_flow_test.go (задача 17), а второй вызов на этот
			// маршрут был бы пятым в bucket'е — ровно тем запасом, который тест
			// не имеет права съедать.
			if s.RefreshToken == a.refresh || s.AccessToken == a.access {
				t.Error("refresh выдал ту же пару")
			}
			return resp.StatusCode
		}},
		{"POST /refresh мусором", http.StatusUnauthorized, "refresh_token_invalid", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": strings.Repeat("z", 48)}, nil)
			return resp.StatusCode
		}},
		{"POST /refresh заблокированного", http.StatusForbidden, "account_locked", func(t *testing.T, e *env) int {
			// Продление сессии — это доступ, а не «посмотреть состояние»: blocked
			// аккаунт нового доступа не получает (задача 17, шаг 4).
			a := e.block(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			return resp.StatusCode
		}},
		{"POST /logout своим refresh и повтор", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			// Два вызова вместо двух строк: отзыв идемпотентен, и второй 204 — то же
			// доказательство, что отдельный случай, только дешевле по bucket'у.
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": a.refresh}, nil)
			if resp.StatusCode != http.StatusNoContent {
				return resp.StatusCode
			}
			again, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": a.refresh}, nil)
			return again.StatusCode
		}},
		{"POST /logout чужим access не отзывает не свою семью", http.StatusOK, "", func(t *testing.T, e *env) int {
			// Целевой вызов здесь — refresh: logout(x-заголовок, refresh y) обязан
			// отозвать семью y и не тронуть семью x. Access в заголовке — только
			// источник jti для denylist, и доказательством владения семьёй он быть не
			// может.
			x := e.mint(t)
			y := e.mint(t)
			lr, body := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": y.refresh}, authHdr(x.access))
			if lr.StatusCode != http.StatusNoContent {
				t.Fatalf("logout = %d %s, want 204", lr.StatusCode, body)
			}
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": x.refresh}, nil)
			return resp.StatusCode
		}},
		{"POST /logout мусором", http.StatusUnauthorized, "refresh_token_invalid", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": strings.Repeat("q", 48)}, nil)
			return resp.StatusCode
		}},
	}
}

func authHdr(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func newIdem() string { return "idem-" + uuid.NewString() }

// idem — свежий ключ на каждый вызов. Повтор ключа нужен ровно одному случаю (конфликт
// тела), и тот берёт его через idemWith.
func idem() map[string]string { return map[string]string{"Idempotency-Key": newIdem()} }

func idemWith(key string) map[string]string { return map[string]string{"Idempotency-Key": key} }

func merge(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func TestAccessMatrix(t *testing.T) {
	e := newEnv(t)
	for _, c := range matrixCases() {
		t.Run(c.name, func(t *testing.T) {
			status := c.run(t, e)
			if status != c.want {
				t.Fatalf("%s: status = %d, want %d", c.name, status, c.want)
			}
			last := e.ev.calls[len(e.ev.calls)-1]
			if c.code == "" {
				if last.status < 200 || last.status >= 300 {
					t.Fatalf("%s: want success, got %d %s", c.name, last.status, last.body)
				}
				return
			}
			if got := codeOf(t, last.body); got != c.code {
				t.Errorf("%s: code = %q, want %q (body %s)", c.name, got, c.code, last.body)
			}
		})
	}
	// 429 в матрице — не «так и задумано»: значит тест съел собственный лимит, и
	// вывод матрицы в этом прогоне недействителен.
	for _, c := range e.ev.calls {
		if c.status == http.StatusTooManyRequests {
			t.Fatalf("%s %s hit the rate limit — reduce anonymous calls below five",
				c.method, c.path)
		}
	}
	checkEvidence(t, e)
}

// checkEvidence — то, ради чего собирался evidence. ТЗ §10 и §15: токены, пароли и
// письма не попадают ни в журнал, ни в чужие ответы; §19.6 запрещает ключевой материал
// в ответах и логах вовсе.
func checkEvidence(t *testing.T, e *env) {
	t.Helper()
	journal := e.log.String()

	for _, s := range e.ev.secrets {
		if len(s.value) < 8 {
			t.Fatalf("secret %q is too short to check meaningfully", s.label)
		}
		// (1) журнал: ни одного секрета, никогда.
		if strings.Contains(journal, s.value) {
			t.Errorf("journal contains %s", s.label)
		}
		// (2) ответ: секрет разрешён только на тех маршрутах, где он выдаётся.
		for _, c := range e.ev.calls {
			if !bytes.Contains(c.body, []byte(s.value)) {
				continue
			}
			allowed := false
			for _, p := range s.allow {
				if c.path == p {
					allowed = true
				}
			}
			if !allowed {
				t.Errorf("%s appears in the answer of %s %s (%d)",
					s.label, c.method, c.path, c.status)
			}
		}
	}

	lower := strings.ToLower(journal)
	for _, marker := range []string{"authorization", "password", "bearer", "private_key",
		"-----begin", "refresh_token"} {
		if strings.Contains(lower, marker) {
			t.Errorf("journal mentions %q", marker)
		}
	}
	// Ответы: приватные ключи и хэши не возвращаются никогда — ни на 2xx, ни на 4xx
	// (в деталях ошибки их тоже быть не должно). Само слово «password» в список не
	// входит осознанно: его содержат разрешённые контрактом сообщения вида
	// «email or password is incorrect» и details «field: password» — а значение
	// пароля проверяется выше, циклом по secrets.
	for _, c := range e.ev.calls {
		lb := strings.ToLower(string(c.body))
		for _, marker := range []string{"private_key", "password_hash", "-----begin"} {
			if strings.Contains(lb, marker) {
				t.Errorf("%s %s (%d) body mentions %q: %s",
					c.method, c.path, c.status, marker, c.body)
			}
		}
		// Письмо — только в /me (контракт Me.user.email). В чужих и ошибочных ответах
		// его быть не может: это оракул «такой адрес есть».
		if c.path != "/api/v1/me" {
			for _, s := range e.ev.secrets {
				if !strings.Contains(s.label, "email") {
					continue
				}
				if bytes.Contains(c.body, []byte(s.value)) {
					t.Errorf("%s %s (%d) leaks %s: %s", c.method, c.path, c.status, s.label, c.body)
				}
			}
		}
	}

	// Журнал обязан содержать маршруты: без них проверка «ops видит, что случилось»
	// превращается в надежду.
	for _, p := range []string{"/api/v1/devices", "/api/v1/me"} {
		if !strings.Contains(journal, p) {
			t.Errorf("journal has no line for %s", p)
		}
	}
}

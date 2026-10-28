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

	// Ниже — источники состояния для A-2. Каждый создаётся ровно один раз: seed и
	// вход в обход роутера, повторённый в каждой строке, проверял бы фикстуру, а не
	// доступ. Узел кэшируется по серверу: бакет лимитера у него на server_id, и второй
	// enroll того же сервера отзывал бы токен, которым уже пользуется соседняя строка.
	adminActor   *adminActor
	nodeActors   map[uuid.UUID]nodeActor
	onlineServer *db.VpnServer
	probeActor   *actor
	// alienSrv — второй узел: его действующий токен предъявляется на пути первого
	// сервера. Один на прогон: enroll гасит прежние токены сервера, и второй enroll
	// того же сервера отобрал бы токен у соседней строки.
	alienSrv *db.VpnServer
}

// adminActor — администратор стенда: токен получен настоящим POST /admin/login, а не
// через Issuer напрямую. Иначе строка «admin» проверяла бы тест, а не маршрут.
type adminActor struct {
	id    uuid.UUID
	email string
	token string
}

// nodeActor — зарегистрированный узел: сервер и выданный ему enroll'ом токен.
type nodeActor struct {
	serverID uuid.UUID
	token    string
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
	e := &env{srv: srv, log: buf, q: q, sess: sess, ev: &evidence{},
		nodeActors: map[uuid.UUID]nodeActor{}}
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

// probe — участник, чей токен матрица предъявляет туда, где он не должен работать:
// на admin- и узловых маршрутах. Один на весь прогон: строк 19, а seedUser с argon2id
// стоит десятки миллисекунд, и девятнадцать одинаковых аккаунтов ничего не доказывают.
func (e *env) probe(t *testing.T) actor {
	t.Helper()
	if e.probeActor == nil {
		a := e.mint(t)
		e.probeActor = &a
	}
	return *e.probeActor
}

// admin — администратор стенда. seedAdmin и настоящий вход через роутер; пароль и
// выданный токен уходят в evidence: ни журнал, ни чужой ответ их содержать не должны.
func (e *env) admin(t *testing.T) adminActor {
	t.Helper()
	if e.adminActor != nil {
		return *e.adminActor
	}
	id, email := seedAdmin(t, context.Background(), e.q)
	e.ev.addSecret("admin password", adminPassword)
	resp, body := raw(t, e, http.MethodPost, "/api/v1/admin/login",
		map[string]string{"email": email, "password": adminPassword}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login = %d %s", resp.StatusCode, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		t.Fatalf("admin login body: %v (%s)", err, body)
	}
	// Токен администратора законен ровно в ответе входа: остальные маршруты его
	// принимают заголовком, а не возвращают.
	e.ev.addSecret("admin access", out.AccessToken, "/api/v1/admin/login")
	a := adminActor{id: id, email: email, token: out.AccessToken}
	e.adminActor = &a
	return a
}

// server — online-сервер стенда. Один на матрицу: выдача профиля требует online, а
// десяток серверов ничего не добавил бы к проверке прав.
func (e *env) server(t *testing.T) db.VpnServer {
	t.Helper()
	if e.onlineServer == nil {
		srv := seedServer(t, context.Background(), e.q, "10.99.90.0/24")
		setServerOnline(t, context.Background(), e.q, srv.ID)
		e.onlineServer = &srv
	}
	return *e.onlineServer
}

// alienServer — узел, чужой для строк «чужой узел»: у него свой действующий токен, а
// путь в запросе принадлежит первому серверу. Отдельный сервер, а не online-фикстура:
// строка «чужой» не имеет права менять набор пиеров, который читают соседние строки.
func (e *env) alienServer(t *testing.T) db.VpnServer {
	t.Helper()
	if e.alienSrv == nil {
		srv := seedServer(t, context.Background(), e.q, "10.99.93.0/24")
		e.alienSrv = &srv
	}
	return *e.alienSrv
}

// node — узел, зарегистрированный по-настоящему: bootstrap-токен выдаётся через
// admin-маршрут, enroll — через /internal/v1 и открытого не требует. Оба секрета
// попадают в evidence: bootstrap законен только в ответе выдачи, узловой токен — в
// ответе enroll и в ответе ротации.
func (e *env) node(t *testing.T, serverID uuid.UUID) nodeActor {
	t.Helper()
	if a, ok := e.nodeActors[serverID]; ok {
		return a
	}
	adm := e.admin(t)
	srv, err := e.q.ServerByID(context.Background(), serverID)
	if err != nil {
		t.Fatalf("ServerByID(%s): %v", serverID, err)
	}
	bootstrapPath := "/api/v1/admin/servers/" + serverID.String() + "/bootstrap-tokens"
	resp, body := raw(t, e, http.MethodPost, bootstrapPath, nil, authHdr(adm.token))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap token = %d %s", resp.StatusCode, body)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.Token == "" {
		t.Fatalf("bootstrap token body: %v (%s)", err, body)
	}
	e.ev.addSecret("bootstrap token/"+serverID.String()[:8], issued.Token, bootstrapPath)

	resp, body = raw(t, e, http.MethodPost, "/internal/v1/nodes/enroll",
		map[string]string{"bootstrap_token": issued.Token, "public_key": srv.PublicKey}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll = %d %s", resp.StatusCode, body)
	}
	var out struct {
		NodeToken string `json:"node_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.NodeToken == "" {
		t.Fatalf("enroll body: %v (%s)", err, body)
	}
	e.ev.addSecret("node token/"+serverID.String()[:8], out.NodeToken,
		"/internal/v1/nodes/enroll", nodePath(serverID, "/token/rotate"))
	a := nodeActor{serverID: serverID, token: out.NodeToken}
	e.nodeActors[serverID] = a
	return a
}

func nodePath(serverID uuid.UUID, suffix string) string {
	return "/internal/v1/nodes/" + serverID.String() + suffix
}

// profileFixture — участник, его устройство и профиль на общем online-сервере.
type profileFixture struct {
	actor  actor
	device db.Device
	server db.VpnServer
}

// withProfile выдаёт профиль тем же маршрутом, что и клиент. Фикстура без выдачи
// (прямой INSERT) проверяла бы таблицы, а не доступ.
func (e *env) withProfile(t *testing.T) profileFixture {
	t.Helper()
	a := e.mint(t)
	d := seedDevice(t, context.Background(), e.q, a.userID, 1)
	srv := e.server(t)
	resp, body := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/profiles",
		map[string]string{"server_id": srv.ID.String()}, merge(authHdr(a.access), idem()))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue profile = %d %s", resp.StatusCode, body)
	}
	return profileFixture{actor: a, device: d, server: srv}
}

func (f profileFixture) profilePath(e *env) string {
	return "/api/v1/devices/" + f.device.ID.String() + "/profiles"
}

func (f profileFixture) onePath() string {
	return "/api/v1/devices/" + f.device.ID.String() + "/profiles/" + f.server.ID.String()
}

// ghostID — существующая по форме строка uuid для строк «аноним» и «чужой токен»:
// отказ приходит до хендлера, и объект с таким id не нужен.
var ghostID = uuid.MustParse("00000000-0000-4000-8000-0000000000aa")

func anonCall(t *testing.T, e *env, method, path string, body any) int {
	t.Helper()
	resp, _ := raw(t, e, method, path, body, nil)
	return resp.StatusCode
}

func probeCall(t *testing.T, e *env, method, path string, body any) int {
	t.Helper()
	resp, _ := raw(t, e, method, path, body, authHdr(e.probe(t).access))
	return resp.StatusCode
}

func adminCall(t *testing.T, e *env, method, path string, body any) int {
	t.Helper()
	resp, _ := raw(t, e, method, path, body, authHdr(e.admin(t).token))
	return resp.StatusCode
}

func nodeCallAs(t *testing.T, e *env, tok, method, path string, body any) int {
	t.Helper()
	resp, _ := raw(t, e, method, path, body, authHdr(tok))
	return resp.StatusCode
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

// publicCases — маршруты участника и каталога: аноним, участник, истёкшая подписка,
// блокировка. Один литерал на весь контур, чтобы одинаковые строки не разъезжались.
// Числа в want/code — не «как удобно», а как обещано в api-spec/openapi.yaml;
// расхождение ловит живая сверка контракта, а не этот список.
func publicCases() []routeCase {
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

		// --- A-2: каталог серверов ---
		// Каталог закрыт аутентификацией, но не подпиской: истёкшая подписка и
		// блокировка видят список, иначе человек не понял бы, что потерял.
		{"GET /servers аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, http.MethodGet, "/api/v1/servers", nil)
		}},
		{"GET /servers участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/servers", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /servers без подписки", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/servers", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /servers заблокированный", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.block(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/servers", nil, authHdr(a.access))
			return resp.StatusCode
		}},

		// --- A-2: отзыв устройства ---
		// Отзыв не спрашивает подписку: закрыть доступ, который уже не оплачен, —
		// законное действие, а не новая выдача.
		{"DELETE /devices/{id} аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, http.MethodDelete, "/api/v1/devices/"+ghostID.String(), nil)
		}},
		{"DELETE /devices/{id} участник", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			resp, _ := raw(t, e, http.MethodDelete, "/api/v1/devices/"+d.ID.String(), nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"DELETE /devices/{id} без подписки", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			resp, _ := raw(t, e, http.MethodDelete, "/api/v1/devices/"+d.ID.String(), nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"DELETE /devices/{id} заблокированный", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			a := e.block(t, e.mint(t))
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			resp, _ := raw(t, e, http.MethodDelete, "/api/v1/devices/"+d.ID.String(), nil, authHdr(a.access))
			return resp.StatusCode
		}},

		// --- A-2: ротация ключа ---
		// Ротация — не новая выдача: лимит устройств и подписка здесь не проверяются,
		// иначе человек с истёкшей подпиской не смог бы даже сменить скомпрометированный
		// ключ. Проверка стоит на создании устройства, а не на каждом шаге цепочки.
		{"POST /devices/{id}/keys/rotate аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+ghostID.String()+"/keys/rotate",
				map[string]string{"public_key": keyFromSeed("rotate-anon-" + uuid.NewString())}, idem())
			return resp.StatusCode
		}},
		{"POST /devices/{id}/keys/rotate участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/keys/rotate",
				map[string]string{"public_key": keyFromSeed("rotate-" + uuid.NewString())},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices/{id}/keys/rotate без подписки", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/keys/rotate",
				map[string]string{"public_key": keyFromSeed("rotate-lapsed-" + uuid.NewString())},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices/{id}/keys/rotate заблокированный", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.block(t, e.mint(t))
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/keys/rotate",
				map[string]string{"public_key": keyFromSeed("rotate-blocked-" + uuid.NewString())},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},

		// --- A-2: выдача профиля ---
		{"POST /devices/{id}/profiles аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+ghostID.String()+"/profiles",
				map[string]string{"server_id": ghostID.String()}, idem())
			return resp.StatusCode
		}},
		{"POST /devices/{id}/profiles участник", http.StatusCreated, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			srv := e.server(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/profiles",
				map[string]string{"server_id": srv.ID.String()}, merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices/{id}/profiles без подписки", http.StatusForbidden, "forbidden", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			srv := e.server(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/profiles",
				map[string]string{"server_id": srv.ID.String()}, merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices/{id}/profiles заблокированный", http.StatusCreated, "", func(t *testing.T, e *env) int {
			// Выдача читает статус устройства и подписку, а статус человека — нет:
			// access заблокированного живёт до истечения AccessTTL (§13.11), и этот
			// замер — часть того же ограничения, а не отдельная дыра.
			a := e.block(t, e.mint(t))
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			srv := e.server(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/profiles",
				map[string]string{"server_id": srv.ID.String()}, merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},

		// --- A-2: чтение профилей ---
		// Чтение — не право на новую выдачу: истёкшая подписка и блокировка видят
		// собственные профили, иначе клиент не отличил бы «доступа нет» от «сервер
		// забыл устройство».
		{"GET /devices/{id}/profiles аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, http.MethodGet, "/api/v1/devices/"+ghostID.String()+"/profiles", nil)
		}},
		{"GET /devices/{id}/profiles участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			resp, _ := raw(t, e, http.MethodGet, f.profilePath(e), nil, authHdr(f.actor.access))
			return resp.StatusCode
		}},
		{"GET /devices/{id}/profiles без подписки", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.lapse(t, f.actor)
			resp, _ := raw(t, e, http.MethodGet, f.profilePath(e), nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices/{id}/profiles заблокированный", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.block(t, f.actor)
			resp, _ := raw(t, e, http.MethodGet, f.profilePath(e), nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices/{id}/profiles/{server_id} аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, http.MethodGet,
				"/api/v1/devices/"+ghostID.String()+"/profiles/"+ghostID.String(), nil)
		}},
		{"GET /devices/{id}/profiles/{server_id} участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			resp, _ := raw(t, e, http.MethodGet, f.onePath(), nil, authHdr(f.actor.access))
			return resp.StatusCode
		}},
		{"GET /devices/{id}/profiles/{server_id} без подписки", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.lapse(t, f.actor)
			resp, _ := raw(t, e, http.MethodGet, f.onePath(), nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices/{id}/profiles/{server_id} заблокированный", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.block(t, f.actor)
			resp, _ := raw(t, e, http.MethodGet, f.onePath(), nil, authHdr(a.access))
			return resp.StatusCode
		}},

		// --- A-2: отзыв профиля ---
		{"DELETE /devices/{id}/profiles/{server_id} аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, http.MethodDelete,
				"/api/v1/devices/"+ghostID.String()+"/profiles/"+ghostID.String(), nil)
		}},
		{"DELETE /devices/{id}/profiles/{server_id} участник", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			resp, _ := raw(t, e, http.MethodDelete, f.onePath(), nil, authHdr(f.actor.access))
			return resp.StatusCode
		}},
		{"DELETE /devices/{id}/profiles/{server_id} без подписки", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.lapse(t, f.actor)
			resp, _ := raw(t, e, http.MethodDelete, f.onePath(), nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"DELETE /devices/{id}/profiles/{server_id} заблокированный", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.block(t, f.actor)
			resp, _ := raw(t, e, http.MethodDelete, f.onePath(), nil, authHdr(a.access))
			return resp.StatusCode
		}},

		// --- A-2: текст конфига ---
		{"GET /devices/{id}/profiles/{server_id}/config аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, http.MethodGet,
				"/api/v1/devices/"+ghostID.String()+"/profiles/"+ghostID.String()+"/config", nil)
		}},
		{"GET /devices/{id}/profiles/{server_id}/config участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			resp, _ := raw(t, e, http.MethodGet, f.onePath()+"/config", nil, authHdr(f.actor.access))
			return resp.StatusCode
		}},
		{"GET /devices/{id}/profiles/{server_id}/config без подписки", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.lapse(t, f.actor)
			resp, _ := raw(t, e, http.MethodGet, f.onePath()+"/config", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices/{id}/profiles/{server_id}/config заблокированный", http.StatusOK, "", func(t *testing.T, e *env) int {
			f := e.withProfile(t)
			a := e.block(t, f.actor)
			resp, _ := raw(t, e, http.MethodGet, f.onePath()+"/config", nil, authHdr(a.access))
			return resp.StatusCode
		}},
	}
}

// adminMatrix — три строки одного маршрута административного контура: аноним и
// участник получают 401 от middleware до лимитера, администратор — 2xx. Путь для
// отказов общий (ghost): объект с таким id не нужен ни одному из них, потому что
// отказ приходит раньше разбора адреса.
func adminMatrix(name, method string, status int, denyPath string,
	run func(t *testing.T, e *env) int) []routeCase {
	return []routeCase{
		{name + " аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, method, denyPath, nil)
		}},
		{name + " участник", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return probeCall(t, e, method, denyPath, nil)
		}},
		{name + " админ", status, "", run},
	}
}

// adminCases — административный контур: вход и 15 закрытых маршрутов. Успешные
// строки заводят собственный сервер или пользователя: DELETE и maintenance меняют
// объект, и общая фикстура сделала бы результат строки зависящим от порядка.
func adminCases() []routeCase {
	cases := []routeCase{
		// Вход — единственный анонимный маршрут контура. Отказы те же, что у входа
		// участника: причина (адрес есть / пароль не тот) видна только в журнале,
		// наружу — один и тот же 401. Сравнение берёт предыдущий вызов, поэтому
		// строки обязаны идти подряд.
		{"POST /admin/login неверный пароль", http.StatusUnauthorized, "invalid_credentials", func(t *testing.T, e *env) int {
			adm := e.admin(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/admin/login",
				map[string]string{"email": adm.email, "password": "wrong-admin-password"}, nil)
			return resp.StatusCode
		}},
		{"POST /admin/login несуществующий адрес неотличим", http.StatusUnauthorized, "invalid_credentials", func(t *testing.T, e *env) int {
			resp, body := raw(t, e, http.MethodPost, "/api/v1/admin/login",
				map[string]string{"email": "ghost-admin-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": adminPassword}, nil)
			prev := e.ev.calls[len(e.ev.calls)-2].body
			if codeAndMessage(t, prev) != codeAndMessage(t, body) {
				t.Errorf("unknown admin email differs from wrong password: %s vs %s", body, prev)
			}
			return resp.StatusCode
		}},
	}

	cases = append(cases, adminMatrix("GET /admin/servers", http.MethodGet, http.StatusOK,
		"/api/v1/admin/servers", func(t *testing.T, e *env) int {
			return adminCall(t, e, http.MethodGet, "/api/v1/admin/servers", nil)
		})...)

	cases = append(cases, adminMatrix("POST /admin/servers", http.MethodPost, http.StatusCreated,
		"/api/v1/admin/servers", func(t *testing.T, e *env) int {
			// Локаль уникальна по (страна, город, координаты): город с суффиксом id,
			// иначе второй прогон на той же dev-базе упёрся бы в UNIQUE.
			return adminCall(t, e, http.MethodPost, "/api/v1/admin/servers",
				newServerBody("adm-"+uuid.NewString()[:8], "matrix-"+uuid.NewString()[:8],
					"10.99.94.0/24", keyFromSeed("admin-matrix-"+uuid.NewString())))
		})...)

	cases = append(cases, adminMatrix("GET /admin/servers/{id}", http.MethodGet, http.StatusOK,
		"/api/v1/admin/servers/"+ghostID.String(), func(t *testing.T, e *env) int {
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			return adminCall(t, e, http.MethodGet, "/api/v1/admin/servers/"+srv.ID.String(), nil)
		})...)

	cases = append(cases, adminMatrix("PATCH /admin/servers/{id}", http.MethodPatch, http.StatusOK,
		"/api/v1/admin/servers/"+ghostID.String(), func(t *testing.T, e *env) int {
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			return adminCall(t, e, http.MethodPatch, "/api/v1/admin/servers/"+srv.ID.String(),
				map[string]any{"name": srv.Name, "advertised_host": srv.AdvertisedHost,
					"listen_port": int(srv.ListenPort), "mtu": 1400, "keepalive_sec": 20,
					"reason": "матрица: правка полей"})
		})...)

	cases = append(cases, adminMatrix("POST /admin/servers/{id}/maintenance", http.MethodPost,
		http.StatusOK, "/api/v1/admin/servers/"+ghostID.String()+"/maintenance",
		func(t *testing.T, e *env) int {
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			return adminCall(t, e, http.MethodPost, "/api/v1/admin/servers/"+srv.ID.String()+"/maintenance",
				map[string]string{"status": "draining", "reason": "матрица: вытеснение"})
		})...)

	cases = append(cases, adminMatrix("DELETE /admin/servers/{id}", http.MethodDelete,
		http.StatusNoContent, "/api/v1/admin/servers/"+ghostID.String(),
		func(t *testing.T, e *env) int {
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			return adminCall(t, e, http.MethodDelete, "/api/v1/admin/servers/"+srv.ID.String(),
				map[string]string{"reason": "матрица: удаление"})
		})...)

	cases = append(cases, adminMatrix("POST /admin/servers/{id}/bootstrap-tokens", http.MethodPost,
		http.StatusCreated, "/api/v1/admin/servers/"+ghostID.String()+"/bootstrap-tokens",
		func(t *testing.T, e *env) int {
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			path := "/api/v1/admin/servers/" + srv.ID.String() + "/bootstrap-tokens"
			resp, body := raw(t, e, http.MethodPost, path, nil, authHdr(e.admin(t).token))
			if resp.StatusCode != http.StatusCreated {
				return resp.StatusCode
			}
			var issued struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(body, &issued); err != nil || issued.Token == "" {
				t.Fatalf("bootstrap token body: %v (%s)", err, body)
			}
			// Секрет законен ровно в ответе выдачи: список его не возвращает, журнал —
			// тем более.
			e.ev.addSecret("bootstrap token/matrix", issued.Token, path)
			return resp.StatusCode
		})...)

	cases = append(cases, adminMatrix("GET /admin/servers/{id}/bootstrap-tokens", http.MethodGet,
		http.StatusOK, "/api/v1/admin/servers/"+ghostID.String()+"/bootstrap-tokens",
		func(t *testing.T, e *env) int {
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			return adminCall(t, e, http.MethodGet,
				"/api/v1/admin/servers/"+srv.ID.String()+"/bootstrap-tokens", nil)
		})...)

	cases = append(cases, adminMatrix("DELETE /admin/bootstrap-tokens/{id}", http.MethodDelete,
		http.StatusNoContent, "/api/v1/admin/bootstrap-tokens/"+ghostID.String(),
		func(t *testing.T, e *env) int {
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			issuePath := "/api/v1/admin/servers/" + srv.ID.String() + "/bootstrap-tokens"
			resp, body := raw(t, e, http.MethodPost, issuePath, nil, authHdr(e.admin(t).token))
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("bootstrap issue = %d %s", resp.StatusCode, body)
			}
			var issued struct {
				ID    string `json:"id"`
				Token string `json:"token"`
			}
			if err := json.Unmarshal(body, &issued); err != nil || issued.ID == "" || issued.Token == "" {
				t.Fatalf("bootstrap issue body: %v (%s)", err, body)
			}
			e.ev.addSecret("bootstrap token/revoked", issued.Token, issuePath)
			// Отзыв живого токена, а не мусора: «отозвать нечего» — отдельный отказ,
			// и он уже проверен в задаче 12.
			return adminCall(t, e, http.MethodDelete, "/api/v1/admin/bootstrap-tokens/"+issued.ID,
				map[string]string{"reason": "матрица: отзыв стартового токена"})
		})...)

	cases = append(cases, adminMatrix("POST /admin/servers/{id}/node-token/revoke", http.MethodPost,
		http.StatusNoContent, "/api/v1/admin/servers/"+ghostID.String()+"/node-token/revoke",
		func(t *testing.T, e *env) int {
			// Свой сервер, а не тот, чей токен читают узловые строки: отзыв гасит все
			// узловые токены сервера, и общая фикстура сломала бы соседнюю проверку.
			srv := seedServer(t, context.Background(), e.q, "10.99.94.0/24")
			return adminCall(t, e, http.MethodPost,
				"/api/v1/admin/servers/"+srv.ID.String()+"/node-token/revoke",
				map[string]string{"reason": "матрица: отзыв узла"})
		})...)

	cases = append(cases, adminMatrix("GET /admin/users/{id}", http.MethodGet, http.StatusOK,
		"/api/v1/admin/users/"+ghostID.String(), func(t *testing.T, e *env) int {
			// Участник probe уже заведён строками отказов: второй аккаунт с тем же
			// ответом ничего не доказывает, а argon2id стоит десятки миллисекунд.
			return adminCall(t, e, http.MethodGet, "/api/v1/admin/users/"+e.probe(t).userID.String(), nil)
		})...)

	cases = append(cases, adminMatrix("POST /admin/users/{id}/lock", http.MethodPost, http.StatusOK,
		"/api/v1/admin/users/"+ghostID.String()+"/lock", func(t *testing.T, e *env) int {
			a := e.mint(t)
			return adminCall(t, e, http.MethodPost, "/api/v1/admin/users/"+a.userID.String()+"/lock",
				map[string]string{"reason": "матрица: блокировка"})
		})...)

	cases = append(cases, adminMatrix("POST /admin/users/{id}/unlock", http.MethodPost, http.StatusOK,
		"/api/v1/admin/users/"+ghostID.String()+"/unlock", func(t *testing.T, e *env) int {
			a := e.block(t, e.mint(t))
			return adminCall(t, e, http.MethodPost, "/api/v1/admin/users/"+a.userID.String()+"/unlock",
				map[string]string{"reason": "матрица: разблокировка"})
		})...)

	cases = append(cases, adminMatrix("POST /admin/admins", http.MethodPost, http.StatusCreated,
		"/api/v1/admin/admins", func(t *testing.T, e *env) int {
			return adminCall(t, e, http.MethodPost, "/api/v1/admin/admins",
				map[string]string{"email": "adm-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": adminPassword})
		})...)

	cases = append(cases, adminMatrix("GET /admin/audit", http.MethodGet, http.StatusOK,
		"/api/v1/admin/audit", func(t *testing.T, e *env) int {
			return adminCall(t, e, http.MethodGet, "/api/v1/admin/audit", nil)
		})...)
	return cases
}

// nodeMatrix — четыре состояния узлового маршрута: без токена, с пользовательским
// токеном, с чужим узловым токеном и со своим. Тело читается только в двух последних
// (авторизация стоит раньше разбора), но передаётся одно и то же: строка «чужой»
// проверяет право на путь, а не форму отчёта.
func nodeMatrix(name, suffix, method string, status int, body func() any,
	run func(t *testing.T, e *env) int) []routeCase {
	return []routeCase{
		{name + " без токена", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, method, nodePath(e.server(t).ID, suffix), body())
		}},
		{name + " с пользовательским токеном", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return probeCall(t, e, method, nodePath(e.server(t).ID, suffix), body())
		}},
		{name + " чужой узел", http.StatusForbidden, "forbidden", func(t *testing.T, e *env) int {
			alien := e.node(t, e.alienServer(t).ID)
			return nodeCallAs(t, e, alien.token, method, nodePath(e.server(t).ID, suffix), body())
		}},
		{name + " свой узел", status, "", run},
	}
}

// nodeCases — контракт узла. Свой узел — online-сервер каталога: у него есть набор
// пиеров, и desired отвечает содержимым, а не пустым набором. Ротация стоит последней:
// она гасит токен, которым пользуются предыдущие строки.
func nodeCases() []routeCase {
	cases := []routeCase{
		// enroll — единственный анонимный маршрут префикса. Заголовок участника в
		// первой строке не случайность: пользовательский JWT не делает из участника
		// узел, но проверка тела идёт раньше сверки стартового токена, поэтому ответ
		// 400, а не 401. Так одна строка покрывает два состояния без пятого вызова в
		// bucket'е route+IP, где запас ровно четыре (два enroll'а делают сами фикстуры).
		{"POST /internal/v1/nodes/enroll без bootstrap-токена", http.StatusBadRequest, "invalid_request", func(t *testing.T, e *env) int {
			return probeCall(t, e, http.MethodPost, "/internal/v1/nodes/enroll",
				map[string]string{"bootstrap_token": "",
					"public_key": keyFromSeed("enroll-empty-" + uuid.NewString())})
		}},
		{"POST /internal/v1/nodes/enroll неизвестным bootstrap-токеном", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			return anonCall(t, e, http.MethodPost, "/internal/v1/nodes/enroll",
				map[string]string{"bootstrap_token": strings.Repeat("A", 43),
					"public_key": keyFromSeed("enroll-unknown-" + uuid.NewString())})
		}},
	}
	observed := func() any {
		return map[string]any{"config_version": 0, "interface_rx_bytes": 0,
			"interface_tx_bytes": 0, "peers": []any{}}
	}
	heartbeat := func() any {
		return map[string]any{"agent_version": "matrix", "agent_uptime_sec": 1,
			"load1": 0.1, "cpu_pct": 1.0, "applied_config_version": 0, "stale": false}
	}

	cases = append(cases, nodeMatrix("GET /internal/v1/nodes/{server_id}/desired",
		"/desired", http.MethodGet, http.StatusOK, func() any { return nil },
		func(t *testing.T, e *env) int {
			own := e.node(t, e.server(t).ID)
			return nodeCallAs(t, e, own.token, http.MethodGet,
				nodePath(own.serverID, "/desired"), nil)
		})...)

	cases = append(cases, nodeMatrix("POST /internal/v1/nodes/{server_id}/observed",
		"/observed", http.MethodPost, http.StatusNoContent, observed,
		func(t *testing.T, e *env) int {
			own := e.node(t, e.server(t).ID)
			return nodeCallAs(t, e, own.token, http.MethodPost,
				nodePath(own.serverID, "/observed"), observed())
		})...)

	cases = append(cases, nodeMatrix("POST /internal/v1/nodes/{server_id}/heartbeat",
		"/heartbeat", http.MethodPost, http.StatusNoContent, heartbeat,
		func(t *testing.T, e *env) int {
			own := e.node(t, e.server(t).ID)
			return nodeCallAs(t, e, own.token, http.MethodPost,
				nodePath(own.serverID, "/heartbeat"), heartbeat())
		})...)

	cases = append(cases, nodeMatrix("POST /internal/v1/nodes/{server_id}/token/rotate",
		"/token/rotate", http.MethodPost, http.StatusOK, func() any { return nil },
		func(t *testing.T, e *env) int {
			own := e.node(t, e.server(t).ID)
			path := nodePath(own.serverID, "/token/rotate")
			resp, body := raw(t, e, http.MethodPost, path, nil, authHdr(own.token))
			if resp.StatusCode != http.StatusOK {
				return resp.StatusCode
			}
			var out struct {
				NodeToken string `json:"node_token"`
			}
			if err := json.Unmarshal(body, &out); err != nil || out.NodeToken == "" {
				t.Fatalf("rotate body: %v (%s)", err, body)
			}
			// Новый токен законен только в ответе ротации; прежний уже отозван и
			// после этой строки не используется.
			e.ev.addSecret("node token/rotated", out.NodeToken, path)
			return resp.StatusCode
		})...)
	return cases
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

// matrixSection — один прогон матрицы: свой роутер и свой чистый Redis (isolatedRedis
// чистит девятую базу при сборке роутера). Разделение вынужденное и замеренное: базовый
// бакет "any" — 300 в минуту с burst 60, то есть длительная скорость 5 запросов в
// секунду. Вся матрица A-2 в одном прогоне делает около 160 вызовов за считанные
// секунды и честно упирается в собственный лимит, а не в проверяемое право. Каждый
// контур — отдельный сценарий со своим бюджетом, и 429 внутри него по-прежнему
// обрывает прогон.
type matrixSection struct {
	name string
	// journalRoutes — маршруты, строки которых обязаны быть в журнале этого прогона.
	// У каждой секции свой роутер и свой журнал, поэтому общий список из A-1 здесь
	// проверял бы отсутствие, а не присутствие.
	journalRoutes []string
	cases         func() []routeCase
}

func matrixSections() []matrixSection {
	return []matrixSection{
		{"участник", []string{"/api/v1/devices", "/api/v1/me"}, publicCases},
		{"администратор", []string{"/api/v1/admin"}, adminCases},
		{"узел", []string{"/internal/v1/nodes"}, nodeCases},
	}
}

func TestAccessMatrix(t *testing.T) {
	for _, s := range matrixSections() {
		t.Run(s.name, func(t *testing.T) {
			runMatrix(t, newEnv(t), s.cases(), s.journalRoutes)
		})
	}
}

func runMatrix(t *testing.T, e *env, cases []routeCase, journalRoutes []string) {
	t.Helper()
	for _, c := range cases {
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
	checkEvidence(t, e, journalRoutes)
}

// checkEvidence — то, ради чего собирался evidence. ТЗ §10 и §15: токены, пароли и
// письма не попадают ни в журнал, ни в чужие ответы; §19.6 запрещает ключевой материал
// в ответах и логах вовсе.
func checkEvidence(t *testing.T, e *env, journalRoutes []string) {
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
	// "password":, а не голое слово: диагностическая причина отказа входа
	// ("bad_password") пишется в журнал законно и слова не выдаёт, а поле с
	// паролем выглядело бы как "password":<значение>.
	for _, marker := range []string{"authorization", `"password":`, "bearer", "private_key",
		"-----begin", "refresh_token", "bootstrap_token", "node_token"} {
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
		// "privatekey" и "presharedkey" — без подчёркивания: так их пишет WireGuard-
		// конфиг (PrivateKey=), и поиск "private_key" этот текст не ловил бы вовсе.
		for _, marker := range []string{"private_key", "password_hash", "-----begin",
			"privatekey", "presharedkey"} {
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
	// превращается в надежду. Список принадлежит секции: у неё свой роутер и свой
	// журнал, и чужих маршрутов в нём быть не может.
	for _, p := range journalRoutes {
		if !strings.Contains(journal, p) {
			t.Errorf("journal has no line for %s", p)
		}
	}
}

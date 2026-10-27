package admin

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/audit"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/httpx"
)

// Формы полей повторяют CHECK миграции 0002. Держать их копией здесь нужно не для
// красоты: без этого админ получил бы 500 с текстом «нарушено ограничение» вместо 400
// с именем поля, а имена полей — часть контракта формы.
var (
	hostShape   = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}$`)
	countryRe   = regexp.MustCompile(`^[A-Z]{2}$`)
	coordRe     = regexp.MustCompile(`^-?[0-9]{1,3}(\.[0-9]{1,6})?$`)
	poolBitsMin = 24
	poolBitsMax = 29
)

// defaultMtu и defaultKeepalive — значения из DEFAULT миграции 0002. Нужны они здесь,
// а не «пусть база подставит»: вставленная строка возвращается ответом целиком, и поле,
// отсутствующее в заявке, обязано иметь то же число в ответе, что ему даст схема.
const (
	defaultMtu       = 1420
	defaultKeepalive = 25
)

// base64Key — каноническая форма публичного ключа из [32]byte. Тот же кодировщик, что
// у регистрации устройства: узел предъявит в `peer public-key` ровно эту строку, и
// любая другая форма стала бы вторым ключом на один и тот же ключ.
func base64Key(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

type locationBody struct {
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Lat         string `json:"lat"`
	Lon         string `json:"lon"`
	Timezone    string `json:"timezone"`
}

type createServerRequest struct {
	Location       locationBody `json:"location"`
	Name           string       `json:"name"`
	AdvertisedHost string       `json:"advertised_host"`
	ListenPort     int32        `json:"listen_port"`
	PublicKey      string       `json:"public_key"`
	AddressPoolV4  string       `json:"address_pool_v4"`
	MTU            *int32       `json:"mtu"`
	KeepaliveSec   *int32       `json:"keepalive_sec"`
	Provider       string       `json:"provider"`
	Region         *string      `json:"region"`
	CapacityMbps   *int32       `json:"capacity_mbps"`
	Reason         string       `json:"reason"`
}

type patchServerRequest struct {
	Name           string `json:"name"`
	AdvertisedHost string `json:"advertised_host"`
	ListenPort     int32  `json:"listen_port"`
	MTU            int32  `json:"mtu"`
	KeepaliveSec   int32  `json:"keepalive_sec"`
	CapacityMbps   *int32 `json:"capacity_mbps"`
	Reason         string `json:"reason"`
}

type maintenanceRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func (h *Handler) listServers(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.subject(w, r); !ok {
		return
	}
	rows, err := h.q.ListAllServers(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	items := make([]serverRow, 0, len(rows))
	for _, row := range rows {
		items = append(items, listView(row))
	}
	h.write(w, r, http.StatusOK, map[string]any{"servers": items})
}

func (h *Handler) createServer(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	var in createServerRequest
	if !h.decode(w, r, &in) {
		return
	}
	key, ok := h.canonicalKey(w, r, in.PublicKey)
	if !ok {
		return
	}
	pool, ok := h.poolPrefix(w, r, in.AddressPoolV4)
	if !ok {
		return
	}
	if !h.serverFields(w, r, in.Name, in.AdvertisedHost, in.ListenPort) {
		return
	}
	if !h.locationFields(w, r, in.Location) {
		return
	}
	// Дефолты берёт схема (mtu 1420, keepalive 25), но ответ обязан назвать те же
	// числа: вставленная строка возвращается целиком, поэтому поле в запросе может
	// отсутствовать, а в ответе — нет.
	mtu, keepalive := int32(defaultMtu), int32(defaultKeepalive)
	if in.MTU != nil {
		mtu = *in.MTU
	}
	if in.KeepaliveSec != nil {
		keepalive = *in.KeepaliveSec
	}
	if ok := h.numberInRange(w, r, "mtu", int64(mtu), 1280, 1420) &&
		h.numberInRange(w, r, "keepalive_sec", int64(keepalive), 5, 120) &&
		h.capacity(w, r, in.CapacityMbps); !ok {
		return
	}

	serverID := uuid.New()
	var created db.VpnServer
	err := audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionServerCreated,
		TargetType: "server", TargetID: serverID.String(),
		Reason:    optionalReason(in.Reason, db.AuditActionServerCreated),
		RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		locationID, err := ensureLocation(r.Context(), tx, in.Location)
		if err != nil {
			return err
		}
		srv, err := tx.InsertServer(r.Context(), db.InsertServerParams{
			ID: serverID, LocationID: locationID, Name: in.Name,
			AdvertisedHost: in.AdvertisedHost, ListenPort: in.ListenPort,
			PublicKey: key, AddressPoolV4: pool, Mtu: mtu, KeepaliveSec: keepalive,
			Provider: in.Provider, Region: in.Region, CapacityMbps: in.CapacityMbps,
		})
		if err != nil {
			// name и public_key — UNIQUE в схеме, и оба означают одно: такой узел уже
			// заведён. Дубликат есть дубликат, и 500 от CONSTRAINT здесь был бы
			// правдивее текст, но бесполезнее для формы.
			if isUniqueViolation(err, "") {
				return ErrServerTaken
			}
			return err
		}
		created = srv
		return nil
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	// maintenance_status и config_version приходят из схемы («зарегистрирован» ≠
	// «работает», версия 0): ответа ради их подменять здесь нечем.
	h.write(w, r, http.StatusCreated, serverViewOf(created, 0))
}

func (h *Handler) getServer(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.subject(w, r); !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	srv, err := h.q.ServerByID(r.Context(), id)
	if noRows(err) {
		h.refuse(w, r, ErrServerUnknown)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	peers, err := h.q.CountActiveProfilesOnServer(r.Context(), id)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	health, err := h.q.ServerHealthOf(r.Context(), id)
	switch {
	case err == nil:
		h.write(w, r, http.StatusOK, serverDetail{
			serverRow: serverViewOf(srv, int32(peers)), Health: healthViewOf(health)})
		return
	case noRows(err):
		// null, а не нули: §13.4 запрещает превращать отсутствие замера в «ноль
		// пиеров» — оператор прочитал бы исправный узел как пустой.
		h.write(w, r, http.StatusOK, serverDetail{serverRow: serverViewOf(srv, int32(peers))})
		return
	default:
		h.internal(w, r, err)
	}
}

func (h *Handler) patchServer(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in patchServerRequest
	if !h.decode(w, r, &in) {
		return
	}
	if !h.serverFields(w, r, in.Name, in.AdvertisedHost, in.ListenPort) {
		return
	}
	if !h.numberInRange(w, r, "mtu", int64(in.MTU), 1280, 1420) ||
		!h.numberInRange(w, r, "keepalive_sec", int64(in.KeepaliveSec), 5, 120) ||
		!h.capacity(w, r, in.CapacityMbps) {
		return
	}

	var updated db.VpnServer
	var version int64
	err := audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionServerUpdated,
		TargetType: "server", TargetID: id.String(),
		Reason:    optionalReason(in.Reason, db.AuditActionServerUpdated),
		RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		srv, err := tx.UpdateServerFields(r.Context(), db.UpdateServerFieldsParams{
			ID: id, Name: in.Name, AdvertisedHost: in.AdvertisedHost,
			ListenPort: in.ListenPort, Mtu: in.MTU, KeepaliveSec: in.KeepaliveSec,
			CapacityMbps: in.CapacityMbps,
		})
		if noRows(err) {
			return ErrServerUnknown
		}
		if err != nil {
			if isUniqueViolation(err, "") {
				return ErrServerTaken
			}
			return err
		}
		updated = srv
		// MTU и keepalive живут в [Peer] каждого клиента, поэтому правка без bump'а
		// оставила бы узлу прежний набор при уже изменённых полях сервера.
		v, err := tx.BumpServerConfigVersion(r.Context(), id)
		if err != nil {
			return err
		}
		version = v
		return nil
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	peers, err := h.q.CountActiveProfilesOnServer(r.Context(), id)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	view := serverViewOf(updated, int32(peers))
	// Версия из bump'а, а не из строки до него: UpdateServerFields возвращает
	// VpnServer с прежним config_version, и показать её — значит соврать на единицу.
	view.ConfigVersion = version
	h.write(w, r, http.StatusOK, view)
}

func (h *Handler) setMaintenance(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in maintenanceRequest
	if !h.decode(w, r, &in) {
		return
	}
	status, ok := maintenanceStatus(in.Status)
	if !ok {
		h.badField(w, r, "status", "должна быть одной из online, draining, maintenance, retired")
		return
	}
	reason, ok := h.requiredReason(w, r, in.Reason)
	if !ok {
		return
	}
	current, err := h.q.ServerByID(r.Context(), id)
	if noRows(err) {
		h.refuse(w, r, ErrServerUnknown)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	// retired — конец, а не пауза. Обратный переход означал бы, что узел с уже
	// выведенной конфигурацией снова начинает набирать пиеров сам собой.
	if current.MaintenanceStatus == db.MaintenanceStatusRetired &&
		status == db.MaintenanceStatusOnline {
		h.refuse(w, r, ErrRetiredToOnline)
		return
	}
	// §9 различает «вытеснение» и «правку»: по аудит-логу оператор должен видеть,
	// что началось вытеснение, а не что кто-то поменял поле.
	action := db.AuditActionServerUpdated
	if status == db.MaintenanceStatusDraining || status == db.MaintenanceStatusRetired {
		action = db.AuditActionServerDrained
	}
	var view maintenanceView
	err = audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: action,
		TargetType: "server", TargetID: id.String(),
		Reason: reason, RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		row, err := tx.SetServerMaintenance(r.Context(), db.SetServerMaintenanceParams{
			ID: id, MaintenanceStatus: status,
		})
		if noRows(err) {
			return ErrServerUnknown
		}
		if err != nil {
			return err
		}
		v, err := tx.BumpServerConfigVersion(r.Context(), id)
		if err != nil {
			return err
		}
		view = maintenanceView{ID: row.ID, Name: row.Name,
			MaintenanceStatus: string(row.MaintenanceStatus), ConfigVersion: v}
		return nil
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	h.write(w, r, http.StatusOK, view)
}

// deleteServer — порядок шага 7 плана: прочитать, назвать число пиеров, и только
// потом трогать что-либо. Чтение идёт до проверки причины не случайно: §7.6 обещает
// админу «сколько пиеров сорвётся» именно как причину отказа, а отказ по полю reason
// у сервера с живыми профилями скрыл бы от оператора настоящую причину.
func (h *Handler) deleteServer(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in maintenanceRequest
	if !h.decodeOptional(w, r, &in) {
		return
	}
	if _, err := h.q.ServerByID(r.Context(), id); noRows(err) {
		h.refuse(w, r, ErrServerUnknown)
		return
	} else if err != nil {
		h.internal(w, r, err)
		return
	}
	peers, err := h.q.CountActiveProfilesOnServer(r.Context(), id)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	if peers > 0 {
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"на сервере ещё "+strconv.FormatInt(peers, 10)+" активных профилей",
			map[string]any{"peers_active": peers})
		return
	}
	reason, ok := h.requiredReason(w, r, in.Reason)
	if !ok {
		return
	}
	err = audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionServerDeleted,
		TargetType: "server", TargetID: id.String(),
		Reason: reason, RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		// Терминальные остатки удаляются без событий на них: superseded без живого
		// преемника желаемый набор уже не отдаёт, а revoked и expired доступа не дают
		// вовсе, и писать «профиль отозван» о мёртвом означало бы научить аудит лгать.
		if _, err := tx.DeleteProfilesByServer(r.Context(), id); err != nil {
			return err
		}
		// health, tunnel_addresses, node_credentials и bootstrap_tokens уходят
		// каскадом; connection_events.server_id — SET NULL, потому что история
		// событий принадлежит пользователям и устройствам, а не серверу.
		return tx.DeleteServer(r.Context(), id)
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ensureLocation ищет локаль по уникальному ключу схемы и вставляет её только когда
// строки нет. Уникальность (country_code, city, lat, lon) живёт в БД, а не в коде:
// два админа, заводящие сервера в одном городе одновременно, не должны получать 500
// из-за того, что один из них прочитал «нет» в тот же момент, что и другой.
func ensureLocation(ctx context.Context, tx *db.Queries, in locationBody) (uuid.UUID, error) {
	key := db.LocationByKeyParams{
		CountryCode: in.CountryCode, City: in.City, Lat: in.Lat, Lon: in.Lon,
	}
	loc, err := tx.LocationByKey(ctx, key)
	if err == nil {
		return loc.ID, nil
	}
	if !noRows(err) {
		return uuid.Nil, err
	}
	loc, err = tx.InsertServerLocation(ctx, db.InsertServerLocationParams{
		ID: uuid.New(), CountryCode: in.CountryCode, City: in.City,
		Lat: in.Lat, Lon: in.Lon, Timezone: in.Timezone,
	})
	if isUniqueViolation(err, "server_locations_country_code_city_lat_lon_key") {
		// Гонка: строку создал сосед. Второе чтение обязано её найти; если нет —
		// это уже не гонка, а разрушенная ссылка, и притворяться ею незачем.
		loc, err = tx.LocationByKey(ctx, key)
		if noRows(err) {
			return uuid.Nil, ErrLocationGone
		}
	}
	if err != nil {
		return uuid.Nil, err
	}
	return loc.ID, nil
}

func (h *Handler) canonicalKey(w http.ResponseWriter, r *http.Request, raw string) (string, bool) {
	key, err := devices.ParsePublicKey(raw)
	if err != nil {
		h.badField(w, r, "public_key", "должна быть канонической base64-строкой публичного ключа WireGuard")
		return "", false
	}
	// Каноничность проверена, поэтому перекодировка даёт ту же строку; возвращаем её,
	// чтобы в базу не попала форма, отличная от той, что узел предъявит в `peer`.
	return base64Key(key), true
}

func (h *Handler) poolPrefix(w http.ResponseWriter, r *http.Request, raw string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.Addr().Is4() {
		h.badField(w, r, "address_pool_v4", "должна быть IPv4-сетью в форме a.b.c.d/m")
		return netip.Prefix{}, false
	}
	// Больше /29 — не «узел на 512 клиентов», а пул, в котором аллокатор задачи 4
	// переберёт половину пространства до первого отказа; меньше /24 — узел, который
	// никто не просил такого размера.
	if p.Bits() < poolBitsMin || p.Bits() > poolBitsMax {
		h.badField(w, r, "address_pool_v4", "должна быть маской от /24 до /29")
		return netip.Prefix{}, false
	}
	if p != p.Masked() {
		h.badField(w, r, "address_pool_v4", "должна быть адресом сети, а не адресом хоста внутри неё")
		return netip.Prefix{}, false
	}
	return p, true
}

func (h *Handler) serverFields(w http.ResponseWriter, r *http.Request, name, host string, port int32) bool {
	n := utf8.RuneCountInString(name)
	if n < 1 || n > 64 {
		h.badField(w, r, "name", "должна быть от 1 до 64 символов")
		return false
	}
	if !hostShape.MatchString(host) {
		h.badField(w, r, "advertised_host", "должна быть именем или адресом без пробелов, длиннее 253 символов не бывает")
		return false
	}
	return h.numberInRange(w, r, "listen_port", int64(port), 1, 65535)
}

func (h *Handler) locationFields(w http.ResponseWriter, r *http.Request, in locationBody) bool {
	if !countryRe.MatchString(in.CountryCode) {
		h.badField(w, r, "location.country_code", "должна быть двумя заглавными латинскими буквами")
		return false
	}
	n := utf8.RuneCountInString(in.City)
	if n < 1 || n > 64 {
		h.badField(w, r, "location.city", "должна быть от 1 до 64 символов")
		return false
	}
	if utf8.RuneCountInString(in.Timezone) < 1 || utf8.RuneCountInString(in.Timezone) > 64 {
		h.badField(w, r, "location.timezone", "должна быть названием часового пояса от 1 до 64 символов")
		return false
	}
	return h.coordinate(w, r, "location.lat", in.Lat, 90) && h.coordinate(w, r, "location.lon", in.Lon, 180)
}

// coordinate — число в строке: numeric(9,6) после override'а задачи 1 приезжает из
// JSON текстом, и проверка «сначала форма, потом база» здесь ровно та же, что для
// прочих полей. Разрешены только цифры, знак и одна десятичная точка — то есть ровно
// то, что numeric примет без округления до другого значения.
func (h *Handler) coordinate(w http.ResponseWriter, r *http.Request, field, raw string, limit float64) bool {
	if !coordRe.MatchString(raw) {
		h.badField(w, r, field, "должна быть числом не длиннее шести знаков после точки")
		return false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v > limit || v < -limit {
		h.badField(w, r, field, "должна быть от "+strconv.FormatFloat(-limit, 'f', 0, 64)+
			" до "+strconv.FormatFloat(limit, 'f', 0, 64))
		return false
	}
	return true
}

func (h *Handler) numberInRange(w http.ResponseWriter, r *http.Request, field string, v, min, max int64) bool {
	if v < min || v > max {
		h.badField(w, r, field, "должно быть от "+strconv.FormatInt(min, 10)+
			" до "+strconv.FormatInt(max, 10))
		return false
	}
	return true
}

// capacity: NULL — «ёмкость не заявлена», 0 и отрицательные — отказ (CHECK
// capacity_mbps > 0). Разрешить ноль означало бы завести сервер, который каталогу
// обещает нулевую пропускную способность.
func (h *Handler) capacity(w http.ResponseWriter, r *http.Request, v *int32) bool {
	if v == nil {
		return true
	}
	return h.numberInRange(w, r, "capacity_mbps", int64(*v), 1, 1_000_000)
}

func maintenanceStatus(s string) (db.MaintenanceStatus, bool) {
	switch db.MaintenanceStatus(s) {
	case db.MaintenanceStatusOnline, db.MaintenanceStatusDraining,
		db.MaintenanceStatusMaintenance, db.MaintenanceStatusRetired:
		return db.MaintenanceStatus(s), true
	default:
		return "", false
	}
}

// write — единственный способ отдать успех. Ошибка кодирования тела приходит сюда
// только вместе с разрушенной формой ответа, то есть с нашей собственной ошибкой, и
// журнал о ней обязан узнать: молчаливый пустой 200 клиент прочитал бы как «серверов
// нет».
func (h *Handler) write(w http.ResponseWriter, r *http.Request, status int, v any) {
	if err := httpx.WriteJSON(w, status, v); err != nil {
		h.log.Error("admin response encode", "err", err,
			"request_id", httpx.RequestIDFromContext(r.Context()))
	}
}

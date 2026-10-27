package admin

import (
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

// Формы ответов. Отдельный тип на каждый, а не строка таблицы: json-имена — часть
// контракта (задача 14), и менять их должны осознанно, а не по случайности правки
// структуры БД.

// session — ответ входа. Идентификатора администратора здесь сознательно нет: он лежит
// в sub токена, а второй источник того же значения обязан когда-нибудь разойтись с
// первым.
type session struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type serverRow struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	AdvertisedHost    string  `json:"advertised_host"`
	ListenPort        int32   `json:"listen_port"`
	PublicKey         string  `json:"public_key"`
	AddressPoolV4     string  `json:"address_pool_v4"`
	MTU               int32   `json:"mtu"`
	KeepaliveSec      int32   `json:"keepalive_sec"`
	ConfigVersion     int64   `json:"config_version"`
	MaintenanceStatus string  `json:"maintenance_status"`
	Provider          string  `json:"provider"`
	Region            *string `json:"region"`
	CapacityMbps      *int32  `json:"capacity_mbps"`
	CountryCode       string  `json:"country_code"`
	City              string  `json:"city"`
	PeersActive       int32   `json:"peers_active"`
}

// serverDetail — список плюс здоровье. Health может быть null, и это не «ноль
// пиеров», а «не измеряли»: §13.4 запрещает превращать отсутствие замера в ноль.
type serverDetail struct {
	serverRow
	Health *healthRow `json:"health"`
}

type healthRow struct {
	ObservedAt           time.Time `json:"observed_at"`
	PeersConfigured      int32     `json:"peers_configured"`
	PeersHandshaked      int32     `json:"peers_handshaked"`
	InterfaceRxBytes     int64     `json:"interface_rx_bytes"`
	InterfaceTxBytes     int64     `json:"interface_tx_bytes"`
	Load1                *string   `json:"load1"`
	CpuPct               *string   `json:"cpu_pct"`
	AppliedConfigVersion int64     `json:"applied_config_version"`
	Status               string    `json:"status"`
	AgentVersion         *string   `json:"agent_version"`
	AgentUptimeSec       *int64    `json:"agent_uptime_sec"`
}

type bootstrapRow struct {
	ID        uuid.UUID `json:"id"`
	ServerID  uuid.UUID `json:"server_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// issuedToken — то, что отдаётся выдачей. Список токенов (bootstrapRow) секрет не
// повторяет: значение показывается один раз, в момент выдачи, и восстановить его
// нечем — в базе лежит только sha256.
type issuedToken struct {
	bootstrapRow
	Token string `json:"token"`
}

// maintenanceView — ответ перевода сервера в служебный статус. Полный serverRow здесь
// не собирается: SetServerMaintenance читает три колонки, а дописывать к ним ради
// формы ещё один запрос означало бы показать админу версию, которой в момент ответа
// уже могло не быть.
type maintenanceView struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	MaintenanceStatus string    `json:"maintenance_status"`
	ConfigVersion     int64     `json:"config_version"`
}

type deviceRow struct {
	ID         uuid.UUID  `json:"id"`
	PublicKey  string     `json:"public_key"`
	Platform   string     `json:"platform"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

type trafficRow struct {
	DeviceID uuid.UUID `json:"device_id"`
	RxBytes  int64     `json:"rx_bytes"`
	TxBytes  int64     `json:"tx_bytes"`
	Days     int32     `json:"days"`
}

// userRow — просмотр аккаунта. Поля password_hash нет ни в запросе (AdminUserView),
// ни в этом типе: «мы просто не показали» не доказывает, что поле не ушло клиенту.
type userRow struct {
	ID           uuid.UUID    `json:"id"`
	Email        string       `json:"email"`
	DisplayName  *string      `json:"display_name"`
	Status       string       `json:"status"`
	LockedReason *string      `json:"locked_reason"`
	Locale       string       `json:"locale"`
	CreatedAt    time.Time    `json:"created_at"`
	Devices      []deviceRow  `json:"devices"`
	Traffic      []trafficRow `json:"traffic"`
}

type lockResult struct {
	ID              uuid.UUID `json:"id"`
	Status          string    `json:"status"`
	ProfilesRevoked int       `json:"profiles_revoked"`
	ServersBumped   int       `json:"servers_bumped"`
}

type adminRow struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type auditRow struct {
	ID         int64     `json:"id"`
	AdminID    *string   `json:"admin_id"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Reason     string    `json:"reason"`
	RequestID  string    `json:"request_id"`
	CreatedAt  time.Time `json:"created_at"`
}

func listView(row db.ListAllServersRow) serverRow {
	return serverRow{
		ID: row.ID.String(), Name: row.Name, AdvertisedHost: row.AdvertisedHost,
		ListenPort: row.ListenPort, PublicKey: row.PublicKey,
		// Пул наружу — строкой: объект из двух полей человек в консоли читает хуже,
		// а Prefix.String() совпадает с тем, что админ вводил.
		AddressPoolV4: row.AddressPoolV4.String(), MTU: row.Mtu,
		KeepaliveSec: row.KeepaliveSec, ConfigVersion: row.ConfigVersion,
		MaintenanceStatus: string(row.MaintenanceStatus), Provider: row.Provider,
		Region: row.Region, CapacityMbps: row.CapacityMbps,
		CountryCode: row.CountryCode, City: row.City, PeersActive: row.PeersActive,
	}
}

// serverViewOf — форма из строки таблицы (после создания и правки): локация в ней не
// читается, поэтому country_code/city остаются пустыми, если их не дозапросили.
func serverViewOf(srv db.VpnServer, peersActive int32) serverRow {
	return serverRow{
		ID: srv.ID.String(), Name: srv.Name, AdvertisedHost: srv.AdvertisedHost,
		ListenPort: srv.ListenPort, PublicKey: srv.PublicKey,
		AddressPoolV4: srv.AddressPoolV4.String(), MTU: srv.Mtu,
		KeepaliveSec: srv.KeepaliveSec, ConfigVersion: srv.ConfigVersion,
		MaintenanceStatus: string(srv.MaintenanceStatus), Provider: srv.Provider,
		Region: srv.Region, CapacityMbps: srv.CapacityMbps,
		PeersActive: peersActive,
	}
}

func healthViewOf(h db.ServerHealth) *healthRow {
	return &healthRow{
		ObservedAt: h.ObservedAt, PeersConfigured: h.PeersConfigured,
		PeersHandshaked:  h.PeersHandshaked,
		InterfaceRxBytes: h.InterfaceRxBytes, InterfaceTxBytes: h.InterfaceTxBytes,
		Load1: h.Load1, CpuPct: h.CpuPct,
		AppliedConfigVersion: h.AppliedConfigVersion, Status: string(h.Status),
		AgentVersion: h.AgentVersion, AgentUptimeSec: h.AgentUptimeSec,
	}
}

func trafficView(rows []db.TrafficByUserSinceRow) []trafficRow {
	out := make([]trafficRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, trafficRow{DeviceID: r.DeviceID, RxBytes: r.RxBytes,
			TxBytes: r.TxBytes, Days: r.Days})
	}
	return out
}

func deviceView(rows []db.Device) []deviceRow {
	out := make([]deviceRow, 0, len(rows))
	for _, d := range rows {
		out = append(out, deviceRow{ID: d.ID, PublicKey: d.PublicKey,
			Platform: string(d.Platform), Name: d.Name,
			CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt})
	}
	return out
}

func auditView(rows []db.AdminAuditLog) []auditRow {
	out := make([]auditRow, 0, len(rows))
	for _, r := range rows {
		var admin *string
		if r.AdminID != nil {
			v := r.AdminID.String()
			admin = &v
		}
		out = append(out, auditRow{ID: r.ID, AdminID: admin, Action: string(r.Action),
			TargetType: r.TargetType, TargetID: r.TargetID, Reason: r.Reason,
			RequestID: r.RequestID, CreatedAt: r.CreatedAt})
	}
	return out
}

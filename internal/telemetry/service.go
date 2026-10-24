package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/db"
)

const (
	PeerCountersTTL = 48 * time.Hour
	HandshakeFresh  = 3 * time.Minute
)

var ErrInvalidReport = errors.New("telemetry: invalid report")

type PeerStat struct {
	PublicKey       string     `json:"public_key"`
	LatestHandshake *time.Time `json:"latest_handshake"`
	RxBytes         int64      `json:"rx_bytes"`
	TxBytes         int64      `json:"tx_bytes"`
}

type ObservedReport struct {
	ConfigVersion    int64      `json:"config_version"`
	InterfaceRxBytes int64      `json:"interface_rx_bytes"`
	InterfaceTxBytes int64      `json:"interface_tx_bytes"`
	Peers            []PeerStat `json:"peers"`
	AppliedAt        time.Time  `json:"applied_at"`
}

type Heartbeat struct {
	AgentVersion         string   `json:"agent_version"`
	AgentUptimeSec       int64    `json:"agent_uptime_sec"`
	Load1                *float64 `json:"load1"`
	CPUPct               *float64 `json:"cpu_pct"`
	AppliedConfigVersion int64    `json:"applied_config_version"`
}

type Service struct {
	pool *pgxpool.Pool
	rdb  *redis.Client
	log  *slog.Logger
}

func NewService(pool *pgxpool.Pool, rdb *redis.Client, log *slog.Logger) *Service {
	return &Service{pool: pool, rdb: rdb, log: log}
}

func (s *Service) IngestObserved(ctx context.Context, serverID uuid.UUID, rep ObservedReport, now time.Time) error {
	if rep.ConfigVersion < 0 || rep.InterfaceRxBytes < 0 || rep.InterfaceTxBytes < 0 || len(rep.Peers) > 4096 {
		return ErrInvalidReport
	}
	keys := make([]string, 0, len(rep.Peers))
	present := make(map[string]bool, len(rep.Peers))
	for _, peer := range rep.Peers {
		if peer.RxBytes < 0 || peer.TxBytes < 0 || present[peer.PublicKey] {
			return ErrInvalidReport
		}
		present[peer.PublicKey] = true
		keys = append(keys, peer.PublicKey)
	}
	for {
		var staged string
		var recovered bool
		err := db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
			if err := q.LockServerRow(ctx, serverID.String()); err != nil {
				return err
			}
			known, err := observedDevices(ctx, q, serverID, keys)
			if err != nil {
				return err
			}
			if err := q.MarkObservedHealth(ctx, db.MarkObservedHealthParams{
				ServerID: serverID, ObservedAt: now,
				PeersConfigured: int32(len(rep.Peers)), PeersHandshaked: int32(CountHandshaked(rep.Peers, now, HandshakeFresh)),
				InterfaceRxBytes: rep.InterfaceRxBytes, InterfaceTxBytes: rep.InterfaceTxBytes,
				AppliedConfigVersion: rep.ConfigVersion,
			}); err != nil {
				return err
			}
			for _, peer := range rep.Peers {
				device, ok := known[peer.PublicKey]
				if !ok || peer.LatestHandshake == nil || peer.LatestHandshake.IsZero() || peer.LatestHandshake.After(now) {
					continue
				}
				if err := q.RecordHandshake(ctx, db.RecordHandshakeParams{
					DeviceID: device.ID, ServerID: serverID, HandshakeAt: peer.LatestHandshake.UTC(), ConfigVersion: rep.ConfigVersion,
				}); err != nil {
					return err
				}
			}
			staged, recovered, err = s.ingestCounters(ctx, q, serverID, rep, keys, present, known, now)
			return err
		})
		if err != nil {
			return fmt.Errorf("telemetry: ingest observed: %w", err)
		}
		if staged != "" {
			if err := acknowledgePacket.Run(ctx, s.rdb, []string{"tsp:" + serverID.String()}, staged).Err(); err != nil {
				s.log.Warn("telemetry: packet acknowledgement deferred", "server_id", serverID)
				break
			}
		}
		if !recovered {
			break
		}
	}
	s.log.Info("telemetry: observed accepted", "server_id", serverID, "config_version", rep.ConfigVersion, "peers", len(rep.Peers))
	return nil
}

func (s *Service) IngestHeartbeat(ctx context.Context, serverID uuid.UUID, hb Heartbeat, now time.Time) error {
	if n := utf8.RuneCountInString(hb.AgentVersion); n < 1 || n > 64 {
		return ErrInvalidReport
	}
	if hb.AgentUptimeSec < 0 || hb.AppliedConfigVersion < 0 || !validMetric(hb.Load1, 999) || !validMetric(hb.CPUPct, 100) {
		return ErrInvalidReport
	}
	if err := db.New(s.pool).MarkServerHealth(ctx, db.MarkServerHealthParams{
		ServerID: serverID, ObservedAt: now, Load1: numeric(hb.Load1), CpuPct: numeric(hb.CPUPct),
		AppliedConfigVersion: hb.AppliedConfigVersion, AgentVersion: &hb.AgentVersion, AgentUptimeSec: &hb.AgentUptimeSec,
	}); err != nil {
		return fmt.Errorf("telemetry: ingest heartbeat: %w", err)
	}
	s.log.Info("telemetry: heartbeat accepted", "server_id", serverID, "config_version", hb.AppliedConfigVersion)
	return nil
}

func validMetric(value *float64, max float64) bool {
	return value == nil || (!math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= 0 && *value <= max)
}

func numeric(value *float64) *string {
	if value == nil {
		return nil
	}
	text := strconv.FormatFloat(*value, 'f', -1, 64)
	return &text
}

func observedDevices(ctx context.Context, q *db.Queries, serverID uuid.UUID, keys []string) (map[string]db.ObservedDevicesByPublicKeysRow, error) {
	rows, err := q.ObservedDevicesByPublicKeys(ctx, db.ObservedDevicesByPublicKeysParams{ServerID: serverID, PublicKeys: keys})
	if err != nil {
		return nil, err
	}
	known := make(map[string]db.ObservedDevicesByPublicKeysRow, len(rows))
	counts := make(map[string]int, len(rows))
	for _, row := range rows {
		counts[row.PublicKey]++
		known[row.PublicKey] = row
	}
	for key, count := range counts {
		if count > 1 {
			delete(known, key)
		}
	}
	return known, nil
}

func counterKey(serverID, deviceID uuid.UUID) string {
	return "tsc:" + serverID.String() + ":" + deviceID.String()
}

type counterPacket struct {
	ID         uuid.UUID
	Increments []db.UpsertDeviceDayTrafficParams
	Events     []db.InsertConnectionEventParams
}

var acknowledgePacket = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
`)

func applyPacket(ctx context.Context, q *db.Queries, serverID uuid.UUID, packet counterPacket) error {
	claimed, err := q.ClaimTelemetryPacket(ctx, db.ClaimTelemetryPacketParams{ID: packet.ID, ServerID: serverID})
	if err != nil || claimed == 0 {
		return err
	}
	for _, increment := range packet.Increments {
		if err := q.UpsertDeviceDayTraffic(ctx, increment); err != nil {
			return err
		}
	}
	for _, event := range packet.Events {
		if err := q.InsertConnectionEvent(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ingestCounters(ctx context.Context, q *db.Queries, serverID uuid.UUID, rep ObservedReport, keys []string, present map[string]bool, known map[string]db.ObservedDevicesByPublicKeysRow, now time.Time) (string, bool, error) {
	packetKey := "tsp:" + serverID.String()
	pending, err := s.rdb.Get(ctx, packetKey).Result()
	if err == nil {
		var packet counterPacket
		if json.Unmarshal([]byte(pending), &packet) == nil {
			return pending, true, applyPacket(ctx, q, serverID, packet)
		}
		// Тело пишет только этот код; разобрать его не значит потерять начисления,
		// но и зацикливать приём телеметрии на 48 часов TTL нельзя.
		s.log.Warn("telemetry: pending packet unreadable, discarded", "server_id", serverID)
		if err := s.rdb.Del(ctx, packetKey).Err(); err != nil {
			s.log.Warn("telemetry: redis unavailable, counters skipped", "server_id", serverID)
			return "", false, nil
		}
	} else if !errors.Is(err, redis.Nil) {
		s.log.Warn("telemetry: redis unavailable, counters skipped", "server_id", serverID)
		return "", false, nil
	}
	setKey := "peers:" + serverID.String()
	read := s.rdb.Pipeline()
	previous := read.SMembers(ctx, setKey)
	bases := make(map[string]*redis.MapStringStringCmd, len(known))
	for key, device := range known {
		bases[key] = read.HGetAll(ctx, counterKey(serverID, device.ID))
	}
	if _, err := read.Exec(ctx); err != nil {
		s.log.Warn("telemetry: redis unavailable, counters skipped", "server_id", serverID)
		return "", false, nil
	}
	old := make(map[string]bool, len(previous.Val()))
	removed := make([]string, 0)
	for _, key := range previous.Val() {
		old[key] = true
		if !present[key] {
			removed = append(removed, key)
		}
	}
	removedDevices, err := observedDevices(ctx, q, serverID, removed)
	if err != nil {
		return "", false, err
	}
	packet := counterPacket{ID: uuid.New()}
	write := s.rdb.TxPipeline()
	for _, peer := range rep.Peers {
		device, ok := known[peer.PublicKey]
		if !ok {
			continue
		}
		base := bases[peer.PublicKey].Val()
		lastRx, rxErr := strconv.ParseInt(base["rx"], 10, 64)
		lastTx, txErr := strconv.ParseInt(base["tx"], 10, 64)
		haveBase := rxErr == nil && txErr == nil && lastRx >= 0 && lastTx >= 0
		rx, tx, reset := Delta(lastRx, lastTx, peer.RxBytes, peer.TxBytes, haveBase)
		if reset {
			s.log.Debug("telemetry: counters reset", "server_id", serverID, "config_version", rep.ConfigVersion)
		}
		if rx > 0 || tx > 0 {
			packet.Increments = append(packet.Increments, db.UpsertDeviceDayTrafficParams{
				UserID: device.UserID, DeviceID: device.ID, Day: DayOf(now), RxBytes: rx, TxBytes: tx,
			})
		}
		key := counterKey(serverID, device.ID)
		write.HSet(ctx, key, "rx", peer.RxBytes, "tx", peer.TxBytes)
		write.PExpire(ctx, key, PeerCountersTTL)
	}
	for _, device := range removedDevices {
		write.Del(ctx, counterKey(serverID, device.ID))
	}
	write.Del(ctx, setKey)
	if len(keys) > 0 {
		members := make([]any, len(keys))
		for i, key := range keys {
			members[i] = key
		}
		write.SAdd(ctx, setKey, members...)
		write.PExpire(ctx, setKey, PeerCountersTTL)
	}
	detail, _ := json.Marshal(struct {
		ConfigVersion int64 `json:"config_version"`
	}{rep.ConfigVersion})
	for key, device := range known {
		if !old[key] {
			packet.Events = append(packet.Events, db.InsertConnectionEventParams{
				UserID: &device.UserID, DeviceID: &device.ID, ServerID: &serverID, Event: db.EventTypePeerApplied, Detail: detail,
			})
		}
	}
	for _, device := range removedDevices {
		packet.Events = append(packet.Events, db.InsertConnectionEventParams{
			UserID: &device.UserID, DeviceID: &device.ID, ServerID: &serverID, Event: db.EventTypePeerRemoved, Detail: detail,
		})
	}
	var staged string
	if len(packet.Increments) > 0 || len(packet.Events) > 0 {
		body, err := json.Marshal(packet)
		if err != nil {
			return "", false, err
		}
		staged = string(body)
		write.Set(ctx, packetKey, staged, PeerCountersTTL)
	}
	if _, err := write.Exec(ctx); err != nil {
		s.log.Warn("telemetry: redis unavailable, counters skipped", "server_id", serverID)
		return "", false, nil
	}
	if staged == "" {
		return "", false, nil
	}
	return staged, false, applyPacket(ctx, q, serverID, packet)
}

//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/servers"
	"github.com/novavpn/novavpn/internal/telemetry"
)

type telemetryFixture struct {
	ctx    context.Context
	q      *db.Queries
	rdb    *redis.Client
	svc    *telemetry.Service
	logs   *bytes.Buffer
	server db.VpnServer
	device db.Device
	now    time.Time
}

func newTelemetryFixture(t *testing.T) telemetryFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	q, rdb := db.New(pool(t)), redisClient(t)
	user := seedUser(t, ctx, q, true)
	srv := seedServer(t, ctx, q, "10.98.10.0/24")
	setServerOnline(t, ctx, q, srv.ID)
	device := seedDevice(t, ctx, q, user, 0)
	seedProfile(t, ctx, q, device.ID, srv.ID, "10.98.10.2", time.Hour)
	logs := &bytes.Buffer{}
	svc := telemetry.NewService(pool(t), rdb, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		_ = rdb.Del(context.Background(), "tsc:"+srv.ID.String()+":"+device.ID.String(),
			"peers:"+srv.ID.String(), "tsp:"+srv.ID.String()).Err()
	})
	return telemetryFixture{ctx: ctx, q: q, rdb: rdb, svc: svc, logs: logs, server: srv, device: device, now: time.Now().UTC().Truncate(time.Microsecond)}
}

func (f telemetryFixture) report(rx, tx int64) telemetry.ObservedReport {
	hs := f.now.Add(-time.Second)
	return telemetry.ObservedReport{ConfigVersion: 7, InterfaceRxBytes: rx, InterfaceTxBytes: tx,
		Peers: []telemetry.PeerStat{{PublicKey: f.device.PublicKey, LatestHandshake: &hs, RxBytes: rx, TxBytes: tx}}}
}

func (f telemetryFixture) ingest(t *testing.T, rep telemetry.ObservedReport) {
	t.Helper()
	if err := f.svc.IngestObserved(f.ctx, f.server.ID, rep, f.now); err != nil {
		t.Fatal(err)
	}
}

func telemetryEventCount(t *testing.T, server, device uuid.UUID, event string) int {
	t.Helper()
	var count int
	if err := pool(t).QueryRow(context.Background(), "SELECT count(*) FROM connection_events WHERE server_id = $1 AND device_id = $2 AND event = $3", server, device, event).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func telemetryTraffic(t *testing.T, device uuid.UUID) (rows int, rx, tx int64) {
	t.Helper()
	if err := pool(t).QueryRow(context.Background(), "SELECT count(*), COALESCE(sum(rx_bytes), 0)::bigint, COALESCE(sum(tx_bytes), 0)::bigint FROM device_day_traffic WHERE device_id = $1", device).Scan(&rows, &rx, &tx); err != nil {
		t.Fatal(err)
	}
	return
}

func TestTelemetryObservedDeltasAndHandshake(t *testing.T) {
	f := newTelemetryFixture(t)
	rep := f.report(5000, 2000)
	f.ingest(t, rep)
	h, err := f.q.ServerHealthOf(f.ctx, f.server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if h.PeersConfigured != 1 || h.PeersHandshaked != 1 || h.AppliedConfigVersion != 7 || h.InterfaceRxBytes != 5000 || h.InterfaceTxBytes != 2000 || !h.ObservedAt.Equal(f.now) {
		t.Fatalf("неверное наблюдение: %+v", h)
	}
	if rows, _, _ := telemetryTraffic(t, f.device.ID); rows != 0 {
		t.Fatal("первый отчёт начислил трафик")
	}
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 1 {
		t.Fatalf("событий handshake: %d", n)
	}
	for _, key := range []string{"tsc:" + f.server.ID.String() + ":" + f.device.ID.String(), "peers:" + f.server.ID.String()} {
		ttl, err := f.rdb.TTL(f.ctx, key).Result()
		if err != nil || ttl < 47*time.Hour || ttl > 48*time.Hour {
			t.Fatalf("TTL = %v, ошибка %v", ttl, err)
		}
	}
	rep.Peers[0].RxBytes, rep.Peers[0].TxBytes = 6000, 2500
	f.ingest(t, rep)
	f.ingest(t, rep)
	if rows, rx, tx := telemetryTraffic(t, f.device.ID); rows != 1 || rx != 1000 || tx != 500 {
		t.Fatalf("агрегат = %d/%d/%d", rows, rx, tx)
	}
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 1 {
		t.Fatalf("повтор handshake: %d", n)
	}
	newHandshake := f.now
	rep.Peers[0].LatestHandshake = &newHandshake
	f.ingest(t, rep)
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 2 {
		t.Fatalf("новый handshake не записан: %d", n)
	}
	rep.InterfaceRxBytes, rep.Peers[0].RxBytes, rep.Peers[0].TxBytes = 10, 10, 5
	f.ingest(t, rep)
	if _, rx, tx := telemetryTraffic(t, f.device.ID); rx != 1000 || tx != 500 {
		t.Fatalf("сброс изменил агрегат: %d/%d", rx, tx)
	}
	h, err = f.q.ServerHealthOf(f.ctx, f.server.ID)
	if err != nil || h.InterfaceRxBytes != 10 {
		t.Fatalf("сброс интерфейса: %+v / %v", h, err)
	}
	if !strings.Contains(f.logs.String(), "counters reset") || strings.Contains(f.logs.String(), f.device.PublicKey) {
		t.Fatal("сброс не отражён в журнале либо раскрыт ключ")
	}
}

func TestHeartbeatStaleMarksHealthStale(t *testing.T) {
	e := newEnv(t)
	srv := e.server(t)
	own := e.node(t, srv.ID)
	hb := map[string]any{
		"agent_version": "test", "agent_uptime_sec": 10,
		"load1": nil, "cpu_pct": nil, "applied_config_version": 7,
	}
	for _, stale := range []bool{true, false, true} {
		hb["stale"] = stale
		resp, body := raw(t, e, http.MethodPost, nodePath(own.serverID, "/heartbeat"), hb, authHdr(own.token))
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("heartbeat при stale=%t: %d %s, ожидался 204", stale, resp.StatusCode, body)
		}
		h, err := e.q.ServerHealthOf(context.Background(), srv.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := db.HealthStatusOk
		if stale {
			want = db.HealthStatusStale
		}
		if h.Status != want {
			t.Fatalf("статус при stale=%t = %q, ожидался %q", stale, h.Status, want)
		}
		if h.AgentVersion == nil || *h.AgentVersion != "test" || h.AgentUptimeSec == nil || *h.AgentUptimeSec != 10 || h.AppliedConfigVersion != 7 || h.Load1 != nil || h.CpuPct != nil {
			t.Fatalf("неверные поля heartbeat: %+v", h)
		}
	}
}

func TestTelemetryObservedPreservesStaleUntilHeartbeat(t *testing.T) {
	for _, source := range []string{"heartbeat", "sweeper"} {
		t.Run(source, func(t *testing.T) {
			e := newEnv(t)
			f := e.withProfile(t)
			own := e.node(t, f.server.ID)
			ctx := context.Background()
			load, cpu := 1.125, 25.5
			hb := telemetry.Heartbeat{AgentVersion: "1.2.3", AgentUptimeSec: 123,
				Load1: &load, CPUPct: &cpu, AppliedConfigVersion: 9, Stale: source == "heartbeat"}
			resp, body := raw(t, e, http.MethodPost, nodePath(own.serverID, "/heartbeat"), hb, authHdr(own.token))
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("первый heartbeat: %d %s", resp.StatusCode, body)
			}
			if source == "sweeper" {
				if _, err := pool(t).Exec(ctx, "UPDATE server_health SET observed_at = now() - interval '200 seconds' WHERE server_id = $1", own.serverID); err != nil {
					t.Fatal(err)
				}
				if _, err := connections.NewStore(pool(t)).SweepStale(ctx, time.Now()); err != nil {
					t.Fatal(err)
				}
				if n := nodeStaleEvents(t, pool(t), own.serverID); n != 1 {
					t.Fatalf("событий node_stale: %d, ожидалось 1", n)
				}
			}
			h, err := e.q.ServerHealthOf(ctx, own.serverID)
			if err != nil || h.Status != db.HealthStatusStale {
				t.Fatalf("до observed ожидался stale: %+v / %v", h, err)
			}
			hs := time.Now().UTC().Add(-time.Second)
			for _, counts := range []struct{ rx, tx, version int64 }{{5000, 2000, 7}, {6000, 2500, 8}} {
				before := h.ObservedAt
				rep := telemetry.ObservedReport{ConfigVersion: counts.version,
					InterfaceRxBytes: counts.rx, InterfaceTxBytes: counts.tx,
					Peers: []telemetry.PeerStat{{PublicKey: f.device.PublicKey, LatestHandshake: &hs, RxBytes: counts.rx, TxBytes: counts.tx}}}
				resp, body = raw(t, e, http.MethodPost, nodePath(own.serverID, "/observed"), rep, authHdr(own.token))
				if resp.StatusCode != http.StatusNoContent {
					t.Fatalf("observed: %d %s", resp.StatusCode, body)
				}
				h, err = e.q.ServerHealthOf(ctx, own.serverID)
				if err != nil {
					t.Fatal(err)
				}
				if h.Status != db.HealthStatusStale {
					t.Errorf("observed снял stale: %q", h.Status)
				}
				if h.AgentVersion == nil || *h.AgentVersion != "1.2.3" || h.AgentUptimeSec == nil || *h.AgentUptimeSec != 123 || h.Load1 == nil || *h.Load1 != "1.125" || h.CpuPct == nil || *h.CpuPct != "25.50" {
					t.Fatalf("observed стёр поля heartbeat: %+v", h)
				}
				if h.PeersConfigured != 1 || h.PeersHandshaked != 1 || h.InterfaceRxBytes != counts.rx || h.InterfaceTxBytes != counts.tx || h.AppliedConfigVersion != counts.version || !h.ObservedAt.After(before) {
					t.Fatalf("observed не обновил измерения: %+v", h)
				}
			}
			hb.Stale = false
			resp, body = raw(t, e, http.MethodPost, nodePath(own.serverID, "/heartbeat"), hb, authHdr(own.token))
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("восстанавливающий heartbeat: %d %s", resp.StatusCode, body)
			}
			h, err = e.q.ServerHealthOf(ctx, own.serverID)
			if err != nil || h.Status != db.HealthStatusOk || h.AppliedConfigVersion != 9 || h.PeersConfigured != 1 || h.PeersHandshaked != 1 || h.InterfaceRxBytes != 6000 || h.InterfaceTxBytes != 2500 {
				t.Fatalf("heartbeat не восстановил ok или стёр observed: %+v / %v", h, err)
			}
		})
	}
}

func TestHeartbeatRequiresExplicitStale(t *testing.T) {
	for _, tc := range []struct {
		name    string
		present bool
		value   any
	}{
		{name: "missing"},
		{name: "null", present: true},
		{name: "string", present: true, value: "true"},
		{name: "number", present: true, value: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			own := e.node(t, e.server(t).ID)
			hb := map[string]any{
				"agent_version": "test", "agent_uptime_sec": 10,
				"load1": 1.125, "cpu_pct": 25.5, "applied_config_version": 7, "stale": true,
			}
			resp, body := raw(t, e, http.MethodPost, nodePath(own.serverID, "/heartbeat"), hb, authHdr(own.token))
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("heartbeat(true): %d %s", resp.StatusCode, body)
			}
			before, err := e.q.ServerHealthOf(context.Background(), own.serverID)
			if err != nil || before.Status != db.HealthStatusStale {
				t.Fatalf("heartbeat(true) не установил stale: %+v / %v", before, err)
			}
			hb["agent_version"], hb["agent_uptime_sec"] = "changed", 20
			hb["load1"], hb["cpu_pct"], hb["applied_config_version"] = nil, nil, 8
			delete(hb, "stale")
			if tc.present {
				hb["stale"] = tc.value
			}
			resp, body = raw(t, e, http.MethodPost, nodePath(own.serverID, "/heartbeat"), hb, authHdr(own.token))
			if resp.StatusCode != http.StatusBadRequest || codeOf(t, body) != "invalid_request" {
				t.Errorf("некорректный stale: %d %s, ожидался 400 invalid_request", resp.StatusCode, body)
			}
			after, err := e.q.ServerHealthOf(context.Background(), own.serverID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Errorf("некорректный heartbeat изменил health: до %+v, после %+v", before, after)
			}
			hb["stale"] = false
			resp, body = raw(t, e, http.MethodPost, nodePath(own.serverID, "/heartbeat"), hb, authHdr(own.token))
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("heartbeat(false): %d %s", resp.StatusCode, body)
			}
			after, err = e.q.ServerHealthOf(context.Background(), own.serverID)
			if err != nil || after.Status != db.HealthStatusOk || after.AgentVersion == nil || *after.AgentVersion != "changed" || after.AgentUptimeSec == nil || *after.AgentUptimeSec != 20 || after.AppliedConfigVersion != 8 || after.Load1 != nil || after.CpuPct != nil || !after.ObservedAt.After(before.ObservedAt) {
				t.Fatalf("heartbeat(false) не принят полностью: %+v / %v", after, err)
			}
		})
	}
}

func TestTelemetryHeartbeatPreservesObservedAndViceVersa(t *testing.T) {
	f := newTelemetryFixture(t)
	load, cpu := 1.125, 25.5
	hb := telemetry.Heartbeat{AgentVersion: "1.2.3", AgentUptimeSec: 123, Load1: &load, CPUPct: &cpu, AppliedConfigVersion: 9}
	if err := f.svc.IngestHeartbeat(f.ctx, f.server.ID, hb, f.now); err != nil {
		t.Fatal(err)
	}
	h, err := f.q.ServerHealthOf(f.ctx, f.server.ID)
	if err != nil || h.PeersConfigured != 0 || h.Status != db.HealthStatusOk {
		t.Fatalf("первый heartbeat: %+v / %v", h, err)
	}
	f.ingest(t, f.report(5000, 2000))
	h, err = f.q.ServerHealthOf(f.ctx, f.server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if h.AgentVersion == nil || *h.AgentVersion != "1.2.3" || h.AgentUptimeSec == nil || *h.AgentUptimeSec != 123 || h.Load1 == nil || *h.Load1 != "1.125" || h.CpuPct == nil || *h.CpuPct != "25.50" {
		t.Fatalf("observed стёр heartbeat: %+v", h)
	}
	hb.Load1, hb.CPUPct = nil, nil
	if err := f.svc.IngestHeartbeat(f.ctx, f.server.ID, hb, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	h, err = f.q.ServerHealthOf(f.ctx, f.server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if h.PeersConfigured != 1 || h.PeersHandshaked != 1 || h.InterfaceRxBytes != 5000 || h.InterfaceTxBytes != 2000 || h.AppliedConfigVersion != 9 || h.Load1 != nil || h.CpuPct != nil {
		t.Fatalf("heartbeat стёр observed или подменил NULL: %+v", h)
	}
	if rows, _, _ := telemetryTraffic(t, f.device.ID); rows != 0 {
		t.Fatal("heartbeat начислил трафик")
	}
}

func TestTelemetryRejectsInvalidReportsBeforeWrites(t *testing.T) {
	f := newTelemetryFixture(t)
	for _, change := range []func(*telemetry.ObservedReport){
		func(r *telemetry.ObservedReport) { r.InterfaceRxBytes = -1 },
		func(r *telemetry.ObservedReport) { r.InterfaceTxBytes = -1 },
		func(r *telemetry.ObservedReport) { r.InterfaceRxBytes = math.MaxInt64 },
		func(r *telemetry.ObservedReport) { r.InterfaceTxBytes = telemetry.MaxCounterBytes + 1 },
		func(r *telemetry.ObservedReport) { r.ConfigVersion = -1 },
		func(r *telemetry.ObservedReport) { r.Peers[0].RxBytes = -1 },
		func(r *telemetry.ObservedReport) { r.Peers[0].TxBytes = -1 },
		func(r *telemetry.ObservedReport) { r.Peers[0].RxBytes = math.MaxInt64 },
		func(r *telemetry.ObservedReport) { r.Peers[0].TxBytes = telemetry.MaxCounterBytes + 1 },
		func(r *telemetry.ObservedReport) { r.Peers = append(r.Peers, r.Peers[0]) },
	} {
		rep := f.report(1, 2)
		change(&rep)
		if err := f.svc.IngestObserved(f.ctx, f.server.ID, rep, f.now); !errors.Is(err, telemetry.ErrInvalidReport) {
			t.Fatalf("невалидный observed: %v", err)
		}
	}
	for _, change := range []func(*telemetry.Heartbeat){
		func(h *telemetry.Heartbeat) { h.AgentVersion = "" },
		func(h *telemetry.Heartbeat) { h.AgentVersion = strings.Repeat("a", 65) },
		func(h *telemetry.Heartbeat) { h.AgentUptimeSec = -1 },
		func(h *telemetry.Heartbeat) { h.AppliedConfigVersion = -1 },
		func(h *telemetry.Heartbeat) { v := -0.1; h.Load1 = &v },
		func(h *telemetry.Heartbeat) { v := 1000.0; h.Load1 = &v },
		func(h *telemetry.Heartbeat) { v := -0.1; h.CPUPct = &v },
		func(h *telemetry.Heartbeat) { v := 100.1; h.CPUPct = &v },
		func(h *telemetry.Heartbeat) { v := math.NaN(); h.CPUPct = &v },
		func(h *telemetry.Heartbeat) { v := math.Inf(1); h.Load1 = &v },
	} {
		hb := telemetry.Heartbeat{AgentVersion: "v1"}
		change(&hb)
		if err := f.svc.IngestHeartbeat(f.ctx, f.server.ID, hb, f.now); !errors.Is(err, telemetry.ErrInvalidReport) {
			t.Fatalf("невалидный heartbeat: %v", err)
		}
	}
	if _, err := f.q.ServerHealthOf(f.ctx, f.server.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("невалидный отчёт записал health: %v", err)
	}
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 0 {
		t.Fatalf("невалидный отчёт записал события: %d", n)
	}
}

func TestTelemetryRedisFailureDoesNotLoseHandshake(t *testing.T) {
	f := newTelemetryFixture(t)
	broken := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond, WriteTimeout: 100 * time.Millisecond})
	defer broken.Close()
	f.svc = telemetry.NewService(pool(t), broken, slog.New(slog.NewJSONHandler(f.logs, nil)))
	f.ingest(t, f.report(5000, 2000))
	rep := f.report(6000, 3000)
	f.ingest(t, rep)
	if _, err := f.q.ServerHealthOf(f.ctx, f.server.ID); err != nil {
		t.Fatal(err)
	}
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 1 {
		t.Fatalf("событий при отказе Redis: %d", n)
	}
	if rows, _, _ := telemetryTraffic(t, f.device.ID); rows != 0 {
		t.Fatal("начислен трафик без Redis")
	}
	if !strings.Contains(f.logs.String(), "redis unavailable") || !strings.Contains(f.logs.String(), "WARN") {
		t.Fatal("нет предупреждения о Redis")
	}
}

func TestTelemetryPeerDiffAndReappearance(t *testing.T) {
	f := newTelemetryFixture(t)
	f.ingest(t, f.report(5000, 2000))
	f.ingest(t, telemetry.ObservedReport{ConfigVersion: 8})
	f.ingest(t, telemetry.ObservedReport{ConfigVersion: 8})
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "peer_removed"); n != 1 {
		t.Fatalf("событий снятия: %d", n)
	}
	f.ingest(t, f.report(9000, 4000))
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "peer_applied"); n != 2 {
		t.Fatalf("событий применения: %d", n)
	}
	if rows, _, _ := telemetryTraffic(t, f.device.ID); rows != 0 {
		t.Fatal("повторное появление использовало старое основание")
	}
}

func TestTelemetryIgnoresUnknownForeignAndAmbiguousKeys(t *testing.T) {
	for _, scenario := range []string{"неизвестный", "другой узел", "коллизия", "будущее время"} {
		t.Run(scenario, func(t *testing.T) {
			f := newTelemetryFixture(t)
			rep := f.report(100, 50)
			switch scenario {
			case "неизвестный":
				rep.Peers[0].PublicKey = keyFromSeed(uuid.NewString())
			case "другой узел":
				foreign := seedDevice(t, f.ctx, f.q, f.device.UserID, 1)
				rep.Peers[0].PublicKey = foreign.PublicKey
			case "коллизия":
				user := seedUser(t, f.ctx, f.q, true)
				d, err := f.q.InsertDevice(f.ctx, db.InsertDeviceParams{ID: uuid.New(), UserID: user, PublicKey: f.device.PublicKey, Platform: db.DevicePlatformLinux, Name: "collision"})
				if err != nil {
					t.Fatal(err)
				}
				seedProfile(t, f.ctx, f.q, d.ID, f.server.ID, "10.98.10.3", time.Hour)
			case "будущее время":
				future := f.now.Add(time.Hour)
				rep.Peers[0].LatestHandshake = &future
			}
			f.ingest(t, rep)
			if scenario != "будущее время" {
				rep.Peers[0].RxBytes++
				f.ingest(t, rep)
			}
			if rows, _, _ := telemetryTraffic(t, f.device.ID); rows != 0 {
				t.Fatal("начислен неподтверждённый трафик")
			}
			var events int
			if err := pool(t).QueryRow(f.ctx, "SELECT count(*) FROM connection_events WHERE server_id = $1 AND event = 'handshake_observed'", f.server.ID).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if events != 0 {
				t.Fatalf("событий неподтверждённого handshake: %d", events)
			}
			h, err := f.q.ServerHealthOf(f.ctx, f.server.ID)
			if err != nil || h.PeersConfigured != 1 {
				t.Fatalf("health проигнорирован: %+v / %v", h, err)
			}
			if scenario == "будущее время" && h.PeersHandshaked != 0 {
				t.Fatal("будущий handshake признан состоявшимся")
			}
		})
	}
}

func TestTelemetryHandshakeIsPerServer(t *testing.T) {
	f := newTelemetryFixture(t)
	other := seedServer(t, f.ctx, f.q, "10.98.11.0/24")
	seedProfile(t, f.ctx, f.q, f.device.ID, other.ID, "10.98.11.2", time.Hour)
	first := f.report(0, 0)
	first.Peers[0].LatestHandshake = &f.now
	f.ingest(t, first)
	second := f.report(0, 0)
	if err := f.svc.IngestObserved(f.ctx, other.ID, second, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.IngestObserved(f.ctx, other.ID, second, f.now); err != nil {
		t.Fatal(err)
	}
	if n := telemetryEventCount(t, other.ID, f.device.ID, "handshake_observed"); n != 1 {
		t.Fatalf("handshake второго сервера потерян или продублирован: %d", n)
	}
	d, err := f.q.DeviceByID(f.ctx, f.device.ID)
	if err != nil || d.LastSeenAt == nil || !d.LastSeenAt.Equal(f.now) {
		t.Fatalf("last_seen_at откатился: %+v / %v", d, err)
	}
}

func TestTelemetryConcurrentReportsAreNotCountedTwice(t *testing.T) {
	f := newTelemetryFixture(t)
	f.ingest(t, f.report(100, 50))
	rep := f.report(200, 100)
	rep.Peers[0].LatestHandshake = &f.now
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc := telemetry.NewService(pool(t), f.rdb, slog.Default())
			errs <- svc.IngestObserved(f.ctx, f.server.ID, rep, f.now)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, rx, tx := telemetryTraffic(t, f.device.ID); rx != 100 || tx != 50 {
		t.Fatalf("повторное начисление: %d/%d", rx, tx)
	}
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 2 {
		t.Fatalf("повтор handshake: %d", n)
	}
}

type failAcknowledgementHook struct{}

func (failAcknowledgementHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (failAcknowledgementHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (failAcknowledgementHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "evalsha" || cmd.Name() == "eval" {
			return errors.New("test: acknowledgement unavailable")
		}
		return next(ctx, cmd)
	}
}

func TestTelemetryDoesNotReplayCommittedPacket(t *testing.T) {
	f := newTelemetryFixture(t)
	f.ingest(t, f.report(100, 50))
	client := redis.NewClient(f.rdb.Options())
	defer client.Close()
	client.AddHook(failAcknowledgementHook{})
	svc := telemetry.NewService(pool(t), client, slog.New(slog.NewJSONHandler(f.logs, nil)))
	rep := f.report(150, 75)
	if err := svc.IngestObserved(f.ctx, f.server.ID, rep, f.now); err != nil {
		t.Fatal(err)
	}
	pendingKey := "tsp:" + f.server.ID.String()
	if exists, err := f.rdb.Exists(f.ctx, pendingKey).Result(); err != nil || exists != 1 {
		t.Fatalf("нет неподтверждённого пакета: %d / %v", exists, err)
	}
	f.ingest(t, rep)
	f.ingest(t, rep)
	if _, rx, tx := telemetryTraffic(t, f.device.ID); rx != 50 || tx != 25 {
		t.Fatalf("повтор подтверждённого пакета: %d/%d", rx, tx)
	}
	if exists, err := f.rdb.Exists(f.ctx, pendingKey).Result(); err != nil || exists != 0 {
		t.Fatalf("пакет не подтверждён: %d / %v", exists, err)
	}
	var receipts int
	if err := pool(t).QueryRow(f.ctx, "SELECT count(*) FROM telemetry_receipts WHERE server_id = $1", f.server.ID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 2 {
		t.Fatalf("квитанций = %d, ожидалось 2", receipts)
	}
}

func TestTelemetryHandshakeLookupUsesScopedIndex(t *testing.T) {
	f := newTelemetryFixture(t)
	if _, err := pool(t).Exec(f.ctx, "INSERT INTO connection_events (server_id, device_id, event, detail) SELECT $1, gen_random_uuid(), 'handshake_observed', jsonb_build_object('handshake_at', now()) FROM generate_series(1, 20000)", f.server.ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool(t).Exec(context.Background(), "DELETE FROM connection_events WHERE server_id = $1", f.server.ID)
	})
	if _, err := pool(t).Exec(f.ctx, "ANALYZE connection_events"); err != nil {
		t.Fatal(err)
	}
	var plan []byte
	if err := pool(t).QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT 1 FROM connection_events WHERE server_id = $1 AND device_id = $2 AND event = 'handshake_observed' AND (detail->>'handshake_at')::timestamptz >= $3", f.server.ID, f.device.ID, f.now).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plan, []byte("connection_events_handshake")) {
		t.Fatalf("индекс не используется: %s", plan)
	}
	t.Logf("план поиска на 20000 событиях: %s", plan)
}

func TestTelemetryRecoversAfterDatabaseRollback(t *testing.T) {
	f := newTelemetryFixture(t)
	f.ingest(t, f.report(100, 50))
	if err := f.q.UpsertDeviceDayTraffic(f.ctx, db.UpsertDeviceDayTrafficParams{
		UserID: f.device.UserID, DeviceID: f.device.ID, Day: telemetry.DayOf(f.now), RxBytes: math.MaxInt64,
	}); err != nil {
		t.Fatal(err)
	}
	second := seedDevice(t, f.ctx, f.q, f.device.UserID, 1)
	seedProfile(t, f.ctx, f.q, second.ID, f.server.ID, "10.98.10.3", time.Hour)
	rep := f.report(150, 75)
	rep.Peers[0].LatestHandshake = &f.now
	rep.Peers = append(rep.Peers, telemetry.PeerStat{PublicKey: second.PublicKey})
	if err := f.svc.IngestObserved(f.ctx, f.server.ID, rep, f.now); err == nil {
		t.Fatal("ожидалась ошибка переполнения агрегата")
	}
	if n := telemetryEventCount(t, f.server.ID, f.device.ID, "handshake_observed"); n != 1 {
		t.Fatalf("handshake не откатился: %d", n)
	}
	if _, err := pool(t).Exec(f.ctx, "UPDATE device_day_traffic SET rx_bytes = 0 WHERE device_id = $1", f.device.ID); err != nil {
		t.Fatal(err)
	}
	f.ingest(t, rep)
	f.ingest(t, rep)
	if _, rx, tx := telemetryTraffic(t, f.device.ID); rx != 50 || tx != 25 {
		t.Fatalf("потеря или повтор дельты после отката: %d/%d", rx, tx)
	}
	if n := telemetryEventCount(t, f.server.ID, second.ID, "peer_applied"); n != 1 {
		t.Fatalf("потеря или повтор применения: %d", n)
	}
}

// TestTelemetryDropsPendingPacketAfterSecondFailure — пакет, который не удаётся
// применить ни при постановке, ни на повторе, снимается: иначе каждый отчёт узла
// повторял бы одну и ту же ошибку до истечения TTL и приём телеметрии был бы
// выключен на 48 часов.
func TestTelemetryDropsPendingPacketAfterSecondFailure(t *testing.T) {
	f := newTelemetryFixture(t)
	f.ingest(t, f.report(100, 50))
	if err := f.q.UpsertDeviceDayTraffic(f.ctx, db.UpsertDeviceDayTrafficParams{
		UserID: f.device.UserID, DeviceID: f.device.ID, Day: telemetry.DayOf(f.now), RxBytes: math.MaxInt64,
	}); err != nil {
		t.Fatal(err)
	}
	rep := f.report(150, 75)
	if err := f.svc.IngestObserved(f.ctx, f.server.ID, rep, f.now); err == nil {
		t.Fatal("ожидалась ошибка переполнения агрегата")
	}
	packetKey := "tsp:" + f.server.ID.String()
	if exists, err := f.rdb.Exists(f.ctx, packetKey).Result(); err != nil || exists != 1 {
		t.Fatalf("неподтверждённый пакет не поставлен: %d / %v", exists, err)
	}

	if err := f.svc.IngestObserved(f.ctx, f.server.ID, rep, f.now); err != nil {
		t.Fatalf("второй отказ не снял пакет: %v", err)
	}
	if exists, err := f.rdb.Exists(f.ctx, packetKey).Result(); err != nil || exists != 0 {
		t.Fatalf("отравленный пакет остался в Redis: %d / %v", exists, err)
	}
	if !strings.Contains(f.logs.String(), "pending packet dropped") {
		t.Fatalf("в журнале нет предупреждения о снятии пакета: %s", f.logs.String())
	}

	// Приём продолжает работать: основания счётчиков сдвинуты неудавшейся попыткой
	// (150/75), поэтому после очистки агрегата считается дельта следующего отчёта.
	if _, err := pool(t).Exec(f.ctx, "UPDATE device_day_traffic SET rx_bytes = 0 WHERE device_id = $1", f.device.ID); err != nil {
		t.Fatal(err)
	}
	f.ingest(t, f.report(200, 100))
	if _, rx, tx := telemetryTraffic(t, f.device.ID); rx != 50 || tx != 25 {
		t.Fatalf("дельта после снятия пакета: %d/%d", rx, tx)
	}
}

func TestTelemetryHandshakeClosesRotationOverlap(t *testing.T) {
	f := newTelemetryFixture(t)
	_, deviceService := rotationHTTP(t)
	child, err := deviceService.RotateKey(f.ctx, f.device.UserID, f.device.ID, keyFromSeed("telemetry-"+f.device.ID.String()))
	if err != nil {
		t.Fatal(err)
	}
	f.now = time.Now().UTC().Truncate(time.Microsecond)
	before, err := servers.Compute(f.ctx, f.q, f.server.ID, f.now)
	if err != nil || len(before.Peers) != 2 {
		t.Fatalf("до handshake: %+v / %v", before, err)
	}
	f.device = child
	rep := f.report(100, 50)
	rep.Peers[0].LatestHandshake = &f.now
	f.ingest(t, rep)
	after, err := servers.Compute(f.ctx, f.q, f.server.ID, time.Now())
	if err != nil || len(after.Peers) != 1 || after.Peers[0].PublicKey != child.PublicKey {
		t.Fatalf("после handshake: %+v / %v", after, err)
	}
}

func TestTelemetryDiscardsUnreadablePendingPacket(t *testing.T) {
	f := newTelemetryFixture(t)
	f.ingest(t, f.report(100, 50))
	packetKey := "tsp:" + f.server.ID.String()
	if err := f.rdb.Set(f.ctx, packetKey, "{telemetry: тело не разбореть", telemetry.PeerCountersTTL).Err(); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.IngestObserved(f.ctx, f.server.ID, f.report(150, 75), f.now); err != nil {
		t.Fatalf("битый неподтверждённый пакет остановил приём телеметрии: %v", err)
	}
	if _, rx, tx := telemetryTraffic(t, f.device.ID); rx != 50 || tx != 25 {
		t.Fatalf("дельта после битого пакета: %d/%d", rx, tx)
	}
	if exists, err := f.rdb.Exists(f.ctx, packetKey).Result(); err != nil || exists != 0 {
		t.Fatalf("битый пакет не выброшен: %d / %v", exists, err)
	}
	if !strings.Contains(f.logs.String(), "pending packet unreadable") {
		t.Fatalf("в журнале нет предупреждения о битом пакете: %s", f.logs.String())
	}
}

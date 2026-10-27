//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/servers"
)

func TestDesiredComputeFiltersProfiles(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	user := seedUser(t, ctx, q, true)
	srv := seedServer(t, ctx, q, "10.97.1.0/24")
	setServerOnline(t, ctx, q, srv.ID)
	var active []db.VpnProfile
	var keys []string
	for i := 0; i < 6; i++ {
		device := seedDevice(t, ctx, q, user, i)
		address := []string{"10.97.1.10", "10.97.1.2", "10.97.1.3", "10.97.1.4", "10.97.1.5", "10.97.1.6"}[i]
		profile := seedProfile(t, ctx, q, device.ID, srv.ID, address, time.Hour)
		switch i {
		case 0, 1:
			active, keys = append(active, profile), append(keys, device.PublicKey)
		case 2:
			if _, err := q.RevokeProfile(ctx, profile.ID); err != nil {
				t.Fatal(err)
			}
		case 3:
			if _, err := q.MarkProfileExpired(ctx, profile.ID); err != nil {
				t.Fatal(err)
			}
		case 4:
			if _, err := p.Exec(ctx, "UPDATE vpn_profiles SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1", profile.ID); err != nil {
				t.Fatal(err)
			}
		case 5:
			if err := q.RevokeDevice(ctx, device.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := time.Now().UTC()
	got, err := servers.Compute(ctx, q, srv.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 2 {
		t.Fatalf("пиры = %+v, ожидались два активных", got.Peers)
	}
	for i, index := range []int{1, 0} {
		peer := got.Peers[i]
		if peer.PublicKey != keys[index] || peer.State != "active" || !slices.Equal(peer.AllowedIPs, []string{active[index].AddressV4.String() + "/32"}) || !peer.ExpiresAt.Equal(active[index].ExpiresAt) {
			t.Fatalf("неверный пир: %+v", peer)
		}
	}
	rows, err := q.DesiredCandidates(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("кандидатов = %d, ожидалось 4 до отсечения срока и устройства", len(rows))
	}
	for _, row := range rows {
		if row.Status != db.ProfileStatusActive {
			t.Fatalf("запрос пропустил снятый профиль: %s", row.Status)
		}
	}
	again, err := servers.Compute(ctx, q, srv.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("ответ нестабилен: %s / %s", firstJSON, secondJSON)
	}
}

func TestDesiredComputeRotation(t *testing.T) {
	for _, name := range []string{
		"открытое окно", "наблюдён новый ключ", "наблюдение на границе", "старое наблюдение",
		"наблюдение другого узла", "наблюдение старого ключа", "закрытое окно",
		"преемник отозван", "устройство преемника отозвано", "удалено устройство",
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := pool(t)
			q := db.New(p)
			user := seedUser(t, ctx, q, true)
			parent := seedDevice(t, ctx, q, user, 0)
			srv := seedServer(t, ctx, q, "10.97.2.0/24")
			setServerOnline(t, ctx, q, srv.ID)
			old := profileOf(t, user, parent.ID, srv.ID)
			svc := devices.NewService(p, entitlements.New(q))
			child, err := svc.RotateKey(ctx, user, parent.ID, keyFromSeed("desired-"+parent.ID.String()))
			if err != nil {
				t.Fatal(err)
			}
			old, err = q.ProfileByID(ctx, old.ID)
			if err != nil {
				t.Fatal(err)
			}
			parent, err = q.DeviceByID(ctx, parent.ID)
			if err != nil {
				t.Fatal(err)
			}
			if parent.RevokedAt == nil || old.OverlapValidUntil == nil {
				t.Fatal("ротация не отозвала предка или не открыла окно")
			}
			newProfile, err := q.ActiveProfileByDeviceServer(ctx, db.ActiveProfileByDeviceServerParams{DeviceID: child.ID, ServerID: srv.ID})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			wantOld, wantNew := true, true
			switch name {
			case "наблюдён новый ключ", "наблюдение на границе", "старое наблюдение", "наблюдение другого узла", "наблюдение старого ключа":
				at, eventServer, eventDevice := now, srv.ID, child.ID
				switch name {
				case "наблюдён новый ключ":
					wantOld = false
				case "наблюдение на границе":
					at, wantOld = now.Add(-10*time.Minute), false
				case "старое наблюдение":
					at = now.Add(-10*time.Minute - time.Microsecond)
				case "наблюдение другого узла":
					eventServer = seedServer(t, ctx, q, "10.97.3.0/24").ID
				case "наблюдение старого ключа":
					eventDevice = parent.ID
				}
				if _, err := p.Exec(ctx, "INSERT INTO connection_events (user_id, device_id, server_id, event, created_at) VALUES ($1, $2, $3, 'handshake_observed', $4)", user, eventDevice, eventServer, at); err != nil {
					t.Fatal(err)
				}
			case "закрытое окно":
				now, wantOld = *old.OverlapValidUntil, false
			case "преемник отозван":
				if _, err := q.RevokeProfile(ctx, newProfile.ID); err != nil {
					t.Fatal(err)
				}
				wantOld, wantNew = false, false
			case "устройство преемника отозвано":
				if err := q.RevokeDevice(ctx, child.ID); err != nil {
					t.Fatal(err)
				}
				wantOld, wantNew = false, false
			case "удалено устройство":
				if _, err := svc.DeleteDevice(ctx, user, child.ID); err != nil {
					t.Fatal(err)
				}
				wantOld, wantNew = false, false
			}
			got, err := servers.Compute(ctx, q, srv.ID, now)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{}
			if wantOld {
				want[parent.PublicKey] = "rotating_old_key"
			}
			if wantNew {
				want[child.PublicKey] = "active"
			}
			if len(got.Peers) != len(want) {
				t.Fatalf("пиры = %+v, ожидались %v", got.Peers, want)
			}
			for _, peer := range got.Peers {
				state, ok := want[peer.PublicKey]
				wantExpiry := old.ExpiresAt
				if state == "rotating_old_key" {
					// Старый ключ живёт не до срока профиля, а до закрытия окна (§7.3):
					// иначе агенту нечем исполнить «окно закрылось, пиер снять».
					wantExpiry = *old.OverlapValidUntil
				}
				if !ok || peer.State != state || !slices.Equal(peer.AllowedIPs, []string{old.AddressV4.String() + "/32"}) || !peer.ExpiresAt.Equal(wantExpiry) {
					t.Fatalf("неверный пир: %+v", peer)
				}
				delete(want, peer.PublicKey)
			}
			if len(want) != 0 {
				t.Fatalf("отсутствуют ключи: %v", want)
			}
		})
	}
}

func TestDesiredComputeSupersededWithoutSuccessor(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	user := seedUser(t, ctx, q, true)
	device := seedDevice(t, ctx, q, user, 0)
	srv := seedServer(t, ctx, q, "10.97.4.0/24")
	setServerOnline(t, ctx, q, srv.ID)
	profile := seedProfile(t, ctx, q, device.ID, srv.ID, "10.97.4.2", time.Hour)
	until := time.Now().Add(10 * time.Minute)
	if _, err := q.SupersedeProfile(ctx, db.SupersedeProfileParams{ID: profile.ID, OverlapValidUntil: &until}); err != nil {
		t.Fatal(err)
	}
	got, err := servers.Compute(ctx, q, srv.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 0 {
		t.Fatalf("предок без преемника попал в набор: %+v", got.Peers)
	}
}

func TestDesiredComputeExcludesCrossUserKeyCollision(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	srv := seedServer(t, ctx, q, "10.97.6.0/24")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUser(t, ctx, q, true)
	first := seedDevice(t, ctx, q, user, 0)
	otherUser := seedUser(t, ctx, q, true)
	second, err := q.InsertDevice(ctx, db.InsertDeviceParams{
		ID: uuid.New(), UserID: otherUser, PublicKey: first.PublicKey,
		Platform: db.DevicePlatformLinux, Name: "same-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	seedProfile(t, ctx, q, first.ID, srv.ID, "10.97.6.2", time.Hour)
	conflict := seedProfile(t, ctx, q, second.ID, srv.ID, "10.97.6.3", time.Hour)
	independent := seedDevice(t, ctx, q, user, 1)
	seedProfile(t, ctx, q, independent.ID, srv.ID, "10.97.6.4", time.Hour)
	got, err := servers.Compute(ctx, q, srv.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 1 || got.Peers[0].PublicKey != independent.PublicKey {
		t.Fatalf("коллизия между пользователями попала в набор: %+v", got.Peers)
	}
	if _, err := q.RevokeProfile(ctx, conflict.ID); err != nil {
		t.Fatal(err)
	}
	got, err = servers.Compute(ctx, q, srv.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 2 || got.Peers[0].PublicKey != first.PublicKey || got.Peers[1].PublicKey != independent.PublicKey {
		t.Fatalf("после снятия коллизии доступ не восстановлен: %+v", got.Peers)
	}
}

func TestDesiredComputeServerStateAndMetadata(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	user := seedUser(t, ctx, q, true)
	device := seedDevice(t, ctx, q, user, 0)
	srv := seedServer(t, ctx, q, "10.97.5.0/24")
	seedProfile(t, ctx, q, device.ID, srv.ID, "10.97.5.2", time.Hour)
	if _, err := p.Exec(ctx, "UPDATE vpn_servers SET mtu = 1380, listen_port = 51971, keepalive_sec = 17, config_version = 42 WHERE id = $1", srv.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().In(time.FixedZone("test", 3*60*60))
	for _, status := range []db.MaintenanceStatus{db.MaintenanceStatusOnline, db.MaintenanceStatusDraining, db.MaintenanceStatusMaintenance, db.MaintenanceStatusRetired} {
		t.Run(string(status), func(t *testing.T) {
			if _, err := q.SetServerMaintenance(ctx, db.SetServerMaintenanceParams{ID: srv.ID, MaintenanceStatus: status}); err != nil {
				t.Fatal(err)
			}
			stored, err := q.ServerByID(ctx, srv.ID)
			if err != nil {
				t.Fatal(err)
			}
			got, err := servers.Compute(ctx, q, srv.ID, now)
			if err != nil {
				t.Fatal(err)
			}
			if got.ServerID != srv.ID.String() || got.ConfigVersion != stored.ConfigVersion || got.MTU != 1380 || got.ListenPort != 51971 || got.KeepaliveSec != 17 || !slices.Equal(got.DNSServers, []string{"10.97.5.1"}) || !got.MeasuredAt.Equal(now) || got.MeasuredAt.Location() != time.UTC {
				t.Fatalf("неверные параметры узла: %+v", got)
			}
			if status == db.MaintenanceStatusOnline {
				if len(got.Peers) != 1 {
					t.Fatalf("пиры online-узла: %+v", got.Peers)
				}
			} else {
				body, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(body, []byte(`"peers":[]`)) {
					t.Fatalf("ожидался пустой массив: %s", body)
				}
			}
		})
	}
	if _, err := servers.Compute(ctx, q, uuid.New(), now); !errors.Is(err, servers.ErrServerUnknown) {
		t.Fatalf("неизвестный сервер: %v", err)
	}
}

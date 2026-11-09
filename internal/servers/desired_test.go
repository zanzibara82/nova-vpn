package servers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

func TestTunnelAddressUsesPoolMask(t *testing.T) {
	for _, tc := range []struct{ pool, want string }{
		{"10.99.7.0/24", "10.99.7.1/24"},
		{"10.99.8.0/29", "10.99.8.1/29"},
	} {
		t.Run(tc.pool, func(t *testing.T) {
			if got := TunnelAddress(netip.MustParsePrefix(tc.pool)); got != tc.want {
				t.Fatalf("TunnelAddress(%s) = %q, ожидался %q", tc.pool, got, tc.want)
			}
		})
	}
}

func desiredCandidate(i int, now time.Time) candidate {
	return candidate{
		ProfileID: uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)),
		DeviceID:  uuid.MustParse(fmt.Sprintf("00000000-0000-4000-9000-%012d", i+1)),
		PublicKey: fmt.Sprintf("k%03d", i),
		Address:   netip.MustParseAddr(fmt.Sprintf("10.99.0.%d", i+2)),
		Status:    db.ProfileStatusActive,
		ExpiresAt: now.Add(time.Hour),
	}
}

func TestSelectPeersAccessRules(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(10*time.Minute)
	for _, tc := range []struct {
		name   string
		change func(*candidate)
		want   bool
	}{
		{"активный", func(c *candidate) {}, true},
		{"отозванное устройство", func(c *candidate) { c.DeviceRevokedAt = &past }, false},
		{"отозванный профиль", func(c *candidate) { c.Status = db.ProfileStatusRevoked }, false},
		{"истёкший статус", func(c *candidate) { c.Status = db.ProfileStatusExpired }, false},
		{"истёкший срок", func(c *candidate) { c.ExpiresAt = past }, false},
		{"граница срока", func(c *candidate) { c.ExpiresAt = now }, false},
		{"нет преемника", func(c *candidate) { c.Status = db.ProfileStatusSuperseded; c.OverlapUntil = &future }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := desiredCandidate(0, now)
			tc.change(&c)
			got := selectPeers([]candidate{c}, nil, now)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("снятый доступ попал в набор: %+v", got)
				}
				return
			}
			want := []Peer{{PublicKey: "k000", AllowedIPs: []string{"10.99.0.2/32"}, ExpiresAt: now.Add(time.Hour), State: "active"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("набор = %+v, ожидался %+v", got, want)
			}
		})
	}
}

func TestSelectPeersRotation(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(10*time.Minute)
	for _, tc := range []struct {
		name      string
		change    func(*candidate, *candidate)
		handshake bool
		want      []string
	}{
		{"два ключа с общим адресом", func(old, next *candidate) {}, false, []string{"k000", "k001"}},
		{"предок отозван ротацией", func(old, next *candidate) { old.DeviceRevokedAt = &past }, false, []string{"k000", "k001"}},
		{"новый ключ наблюдён", func(old, next *candidate) {}, true, []string{"k001"}},
		{"окно отсутствует", func(old, next *candidate) { old.OverlapUntil = nil }, false, []string{"k001"}},
		{"окно закрыто", func(old, next *candidate) { old.OverlapUntil = &past }, false, []string{"k001"}},
		{"граница окна", func(old, next *candidate) { old.OverlapUntil = &now }, false, []string{"k001"}},
		{"срок предка истёк", func(old, next *candidate) { old.ExpiresAt = now }, false, []string{"k001"}},
		{"устройство преемника отозвано", func(old, next *candidate) { next.DeviceRevokedAt = &past }, false, []string{}},
		{"профиль преемника отозван", func(old, next *candidate) { next.Status = db.ProfileStatusRevoked }, false, []string{}},
		{"профиль преемника истёк", func(old, next *candidate) { next.Status = db.ProfileStatusExpired }, false, []string{}},
		{"преемник уже заменён", func(old, next *candidate) { next.Status = db.ProfileStatusSuperseded }, false, []string{}},
		{"срок преемника истёк", func(old, next *candidate) { next.ExpiresAt = now }, false, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, next := desiredCandidate(0, now), desiredCandidate(1, now)
			old.Status, old.OverlapUntil = db.ProfileStatusSuperseded, &future
			next.RotateFrom, next.Address = &old.ProfileID, old.Address
			tc.change(&old, &next)
			got := selectPeers([]candidate{next, old}, map[uuid.UUID]bool{next.DeviceID: tc.handshake}, now)
			keys := make([]string, 0, len(got))
			for _, p := range got {
				keys = append(keys, p.PublicKey)
				state, wantExpiry := "active", now.Add(time.Hour)
				if p.PublicKey == old.PublicKey {
					state, wantExpiry = "rotating_old_key", *old.OverlapUntil
				}
				if p.State != state || !slices.Equal(p.AllowedIPs, []string{"10.99.0.2/32"}) || !p.ExpiresAt.Equal(wantExpiry) {
					t.Fatalf("неверные данные пира: %+v", p)
				}
			}
			if !slices.Equal(keys, tc.want) {
				t.Fatalf("ключи = %v, ожидались %v", keys, tc.want)
			}
		})
	}
}

func TestSelectPeersSortsNumericallyWithoutChangingInput(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.FixedZone("test", 3*60*60))
	a, b, c := desiredCandidate(0, now), desiredCandidate(1, now), desiredCandidate(2, now)
	a.Address = netip.MustParseAddr("10.99.0.10")
	b.Address = netip.MustParseAddr("10.99.0.2")
	c.Address = netip.MustParseAddr("10.99.0.3")
	in := []candidate{a, c, b}
	before := slices.Clone(in)
	got := selectPeers(in, nil, now)
	keys := make([]string, 0, len(got))
	for _, p := range got {
		keys = append(keys, p.PublicKey)
		if p.ExpiresAt.Location() != time.UTC {
			t.Fatalf("срок не приведён к UTC: %v", p.ExpiresAt)
		}
	}
	if !slices.Equal(keys, []string{"k001", "k002", "k000"}) {
		t.Fatalf("нечисловой порядок адресов: %v", keys)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("изменён входной срез")
	}
	if got := selectPeers(nil, nil, now); got == nil || len(got) != 0 {
		t.Fatalf("пустой набор = %#v, ожидался пустой массив", got)
	}
}

func TestSelectPeersExcludesAmbiguousKeys(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	a, b, independent := desiredCandidate(0, now), desiredCandidate(1, now), desiredCandidate(2, now)
	b.PublicKey = a.PublicKey
	got := selectPeers([]candidate{a, b, independent}, nil, now)
	if len(got) != 1 || got[0].PublicKey != independent.PublicKey {
		t.Fatalf("неоднозначный ключ не исключён: %+v", got)
	}
	b.Status = db.ProfileStatusRevoked
	got = selectPeers([]candidate{a, b, independent}, nil, now)
	if len(got) != 2 || got[0].PublicKey != a.PublicKey || got[1].PublicKey != independent.PublicKey {
		t.Fatalf("снятый профиль мешает однозначному ключу: %+v", got)
	}
	if got := selectPeers([]candidate{a, a}, nil, now); got == nil || len(got) != 0 {
		t.Fatalf("ожидался пустой массив при коллизии: %+v", got)
	}
}

func TestDesiredSetNeverContainsRemovedAccess(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	rng := rand.New(rand.NewSource(20261024))
	statuses := []db.ProfileStatus{db.ProfileStatusActive, db.ProfileStatusSuperseded, db.ProfileStatusRevoked, db.ProfileStatusExpired}
	for iteration := 0; iteration < 1000; iteration++ {
		cands := make([]candidate, 0, 12)
		handshaked := make(map[uuid.UUID]bool)
		for i, n := 0, 1+rng.Intn(12); i < n; i++ {
			c := desiredCandidate(i, now)
			c.Status = statuses[rng.Intn(len(statuses))]
			c.ExpiresAt = now.Add(time.Duration(rng.Intn(60*24*3600)-30*24*3600) * time.Second)
			if rng.Intn(3) != 0 {
				at := now.Add(time.Duration(rng.Intn(1201)-600) * time.Second)
				c.OverlapUntil = &at
			}
			if rng.Intn(2) == 0 {
				at := now.Add(-time.Hour)
				c.DeviceRevokedAt = &at
			}
			if i > 0 && rng.Intn(3) == 0 {
				id := cands[i-1].ProfileID
				c.RotateFrom, c.Address = &id, cands[i-1].Address
			}
			handshaked[c.DeviceID] = rng.Intn(2) == 0
			cands = append(cands, c)
		}
		got := selectPeers(cands, handshaked, now)
		if len(got) > len(cands) {
			t.Fatalf("итерация %d: пиров больше кандидатов", iteration)
		}
		seen := make(map[string]bool)
		for _, p := range got {
			if seen[p.PublicKey] {
				t.Fatalf("итерация %d: повтор ключа %s", iteration, p.PublicKey)
			}
			seen[p.PublicKey] = true
			index := slices.IndexFunc(cands, func(c candidate) bool { return c.PublicKey == p.PublicKey })
			if index < 0 {
				t.Fatalf("итерация %d: неизвестный ключ %s", iteration, p.PublicKey)
			}
			c := cands[index]
			// Срок пиера — момент, когда он больше не нужен: у активного это срок
			// профиля, у старого ключа — закрытие overlap-окна (§7.3).
			wantExpiry := c.ExpiresAt
			if p.State == "rotating_old_key" {
				wantExpiry = *c.OverlapUntil
			}
			if !c.ExpiresAt.After(now) || !p.ExpiresAt.Equal(wantExpiry) {
				t.Fatalf("итерация %d: неверный срок", iteration)
			}
			if !slices.Equal(p.AllowedIPs, []string{c.Address.String() + "/32"}) {
				t.Fatalf("итерация %d: неверные маршруты %v", iteration, p.AllowedIPs)
			}
			switch p.State {
			case "active":
				if c.Status != db.ProfileStatusActive || c.DeviceRevokedAt != nil {
					t.Fatalf("итерация %d: снятый активный доступ", iteration)
				}
			case "rotating_old_key":
				if c.Status != db.ProfileStatusSuperseded || c.OverlapUntil == nil || !c.OverlapUntil.After(now) {
					t.Fatalf("итерация %d: закрытое окно", iteration)
				}
				index := slices.IndexFunc(cands, func(next candidate) bool { return next.RotateFrom != nil && *next.RotateFrom == c.ProfileID })
				if index < 0 {
					t.Fatalf("итерация %d: нет преемника", iteration)
				}
				next := cands[index]
				if next.Status != db.ProfileStatusActive || next.DeviceRevokedAt != nil || !next.ExpiresAt.After(now) || handshaked[next.DeviceID] {
					t.Fatalf("итерация %d: старый ключ без основания", iteration)
				}
			default:
				t.Fatalf("итерация %d: неизвестное состояние %q", iteration, p.State)
			}
		}
		original, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		reversed := slices.Clone(cands)
		slices.Reverse(reversed)
		again, err := json.Marshal(selectPeers(reversed, handshaked, now))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, again) {
			t.Fatalf("итерация %d: порядок зависит от входа: %s / %s", iteration, original, again)
		}
	}
}

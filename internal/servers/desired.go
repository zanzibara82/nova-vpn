package servers

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
)

type Peer struct {
	PublicKey  string    `json:"public_key"`
	AllowedIPs []string  `json:"allowed_ips"`
	ExpiresAt  time.Time `json:"expires_at"`
	State      string    `json:"state"`
}

type DesiredSet struct {
	ServerID      string    `json:"server_id"`
	ConfigVersion int64     `json:"config_version"`
	MTU           int       `json:"mtu"`
	ListenPort    int       `json:"listen_port"`
	DNSServers    []string  `json:"dns_servers"`
	KeepaliveSec  int       `json:"keepalive_sec"`
	Peers         []Peer    `json:"peers"`
	MeasuredAt    time.Time `json:"measured_at"`
}

type candidate struct {
	ProfileID       uuid.UUID
	DeviceID        uuid.UUID
	PublicKey       string
	Address         netip.Addr
	Status          db.ProfileStatus
	ExpiresAt       time.Time
	OverlapUntil    *time.Time
	RotateFrom      *uuid.UUID
	DeviceRevokedAt *time.Time
}

var ErrServerUnknown = errors.New("servers: server not found")

func Compute(ctx context.Context, q *db.Queries, serverID uuid.UUID, now time.Time) (DesiredSet, error) {
	srv, err := q.ServerByID(ctx, serverID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DesiredSet{}, ErrServerUnknown
	}
	if err != nil {
		return DesiredSet{}, fmt.Errorf("servers: server by id: %w", err)
	}
	out := DesiredSet{
		ServerID: serverID.String(), ConfigVersion: srv.ConfigVersion,
		MTU: int(srv.Mtu), ListenPort: int(srv.ListenPort),
		DNSServers:   []string{connections.NodeTunnelAddress(srv.AddressPoolV4).String()},
		KeepaliveSec: int(srv.KeepaliveSec), Peers: []Peer{}, MeasuredAt: now.UTC(),
	}
	if srv.MaintenanceStatus != db.MaintenanceStatusOnline {
		return out, nil
	}
	rows, err := q.DesiredCandidates(ctx, serverID)
	if err != nil {
		return DesiredSet{}, fmt.Errorf("servers: desired candidates: %w", err)
	}
	cands := make([]candidate, 0, len(rows))
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		cands = append(cands, candidate{
			ProfileID: row.ID, DeviceID: row.DeviceID, PublicKey: row.PublicKey,
			Address: row.AddressV4, Status: row.Status, ExpiresAt: row.ExpiresAt,
			OverlapUntil: row.OverlapValidUntil, RotateFrom: row.RotateFrom,
			DeviceRevokedAt: row.DeviceRevokedAt,
		})
		if row.RotateFrom != nil {
			ids = append(ids, row.DeviceID)
		}
	}
	handshaked := make(map[uuid.UUID]bool)
	if len(ids) > 0 {
		observed, err := q.HandshakedDevicesAfter(ctx, db.HandshakedDevicesAfterParams{
			ServerID: &serverID, CreatedAt: now.Add(-connections.RotationOverlap), Column3: ids,
		})
		if err != nil {
			return DesiredSet{}, fmt.Errorf("servers: observed handshakes: %w", err)
		}
		for _, id := range observed {
			if id != nil {
				handshaked[*id] = true
			}
		}
	}
	out.Peers = selectPeers(cands, handshaked, now)
	return out, nil
}

func selectPeers(cands []candidate, handshaked map[uuid.UUID]bool, now time.Time) []Peer {
	successor := make(map[uuid.UUID]candidate, len(cands))
	for _, c := range cands {
		if c.RotateFrom != nil {
			successor[*c.RotateFrom] = c
		}
	}
	sorted := slices.Clone(cands)
	slices.SortFunc(sorted, func(a, b candidate) int {
		if order := a.Address.Compare(b.Address); order != 0 {
			return order
		}
		return cmp.Compare(a.PublicKey, b.PublicKey)
	})
	peers := make([]Peer, 0, len(cands))
	for _, c := range sorted {
		if !c.ExpiresAt.After(now) {
			continue
		}
		var state string
		switch c.Status {
		case db.ProfileStatusActive:
			if c.DeviceRevokedAt != nil {
				continue
			}
			state = string(db.PeerStateActive)
		case db.ProfileStatusSuperseded:
			// Ротация отзывает старое устройство, но сохраняет его ключ до закрытия окна.
			next, ok := successor[c.ProfileID]
			if !ok || next.Status != db.ProfileStatusActive || next.DeviceRevokedAt != nil || !next.ExpiresAt.After(now) {
				continue
			}
			if c.OverlapUntil == nil || !c.OverlapUntil.After(now) || handshaked[next.DeviceID] {
				continue
			}
			state = string(db.PeerStateRotatingOldKey)
		default:
			continue
		}
		peers = append(peers, Peer{
			PublicKey:  c.PublicKey,
			AllowedIPs: []string{c.Address.String() + "/32"},
			ExpiresAt:  c.ExpiresAt.UTC(),
			State:      state,
		})
	}
	counts := make(map[string]int, len(peers))
	for _, peer := range peers {
		counts[peer.PublicKey]++
	}
	// Ключ не уникален между пользователями; при коллизии нельзя выбирать владельца.
	return slices.DeleteFunc(peers, func(peer Peer) bool {
		return counts[peer.PublicKey] > 1
	})
}

package runtime

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/novavpn/novavpn/internal/nodeagent/api"
	"github.com/novavpn/novavpn/internal/nodeagent/state"
	"github.com/novavpn/novavpn/internal/nodeagent/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type API interface {
	SetToken(string)
	Desired(context.Context, string, string) (api.DesiredSet, string, bool, error)
	Observed(context.Context, string, api.ObservedReport) error
	Heartbeat(context.Context, string, api.Heartbeat) error
	RotateToken(context.Context, string) (api.NodeToken, error)
}

type Applier interface {
	Apply(wg.Target) (wg.ApplyResult, error)
	Snapshot() (wg.LiveState, error)
}

type Store interface {
	Load() (state.NodeState, error)
	Save(state.NodeState) error
	PrivateKey() (wgtypes.Key, error)
}

type Runner struct {
	API                API
	Applier            Applier
	Store              Store
	Log                *slog.Logger
	Iface              string
	Interval, TokenTTL time.Duration
	Version            string
	Now                func() time.Time
	started            time.Time
	reconciled         bool
	after              func(time.Duration) <-chan time.Time
	pendingState       *state.NodeState
}

func (r *Runner) Step(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.started.IsZero() {
		r.started = r.Now()
	}
	if r.pendingState != nil {
		if err := r.Store.Save(*r.pendingState); err != nil {
			return r.failure("повторная запись токена не удалась")
		}
		r.pendingState = nil
	}
	st, err := r.Store.Load()
	if err != nil {
		return r.failure("чтение состояния не удалось")
	}
	if st.ServerID == "" || st.NodeToken == "" {
		return r.failure("узел не зарегистрирован")
	}
	r.API.SetToken(st.NodeToken)
	etag := ""
	if r.reconciled {
		etag = st.Applied.ETag
	}
	set, newETag, notModified, err := r.API.Desired(ctx, st.ServerID, etag)
	if err != nil {
		r.failure("получение желаемого набора не удалось")
		r.heartbeat(ctx, st, true)
		return nil
	}
	var live wg.LiveState
	if notModified {
		if !r.reconciled || etag == "" {
			r.reconciled = false
			r.heartbeat(ctx, st, true)
			return r.failure("ответ 304 без условного запроса")
		}
		live, err = r.Applier.Snapshot()
		if err != nil {
			r.heartbeat(ctx, st, false)
			return r.failure("получение снимка не удалось")
		}
	} else {
		if set.ServerID != st.ServerID {
			r.heartbeat(ctx, st, true)
			return r.failure("набор предназначен другому узлу")
		}
		key, err := r.Store.PrivateKey()
		if err != nil {
			r.heartbeat(ctx, st, true)
			return r.failure("чтение приватного ключа не удалось")
		}
		target, err := targetFrom(set, key)
		if err != nil {
			r.heartbeat(ctx, st, true)
			return r.failure("преобразование желаемого набора не удалось")
		}
		res, err := r.Applier.Apply(target)
		if err != nil {
			r.failure("применение желаемого набора не удалось")
			r.heartbeat(ctx, st, false)
			return nil
		}
		st.Applied = state.Applied{ConfigVersion: set.ConfigVersion, ETag: newETag, AppliedAt: r.Now().UTC(), Peers: len(set.Peers)}
		if err := r.Store.Save(st); err != nil {
			r.reconciled = false
			return r.failure("запись применённого набора не удалась")
		}
		r.reconciled = true
		live = res.Before
	}
	if err := r.API.Observed(ctx, st.ServerID, report(st.Applied.ConfigVersion, live)); err != nil {
		r.failure("отправка отчёта о состоянии не удалась")
	}
	r.heartbeat(ctx, st, false)
	return r.rotate(ctx, st)
}

func (r *Runner) rotate(ctx context.Context, st state.NodeState) error {
	ttl := r.TokenTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if r.Now().Sub(st.TokenIssuedAt) < ttl {
		return nil
	}
	token, err := r.API.RotateToken(ctx, st.ServerID)
	if err != nil {
		return r.failure("ротация токена не удалась")
	}
	if token.NodeToken == "" || token.ServerID != st.ServerID {
		return r.failure("неверный ответ ротации токена")
	}
	st.NodeToken = token.NodeToken
	st.TokenIssuedAt = r.Now().UTC()
	r.API.SetToken(st.NodeToken)
	if err := r.Store.Save(st); err != nil {
		r.pendingState = &st
		return r.failure("запись нового токена не удалась")
	}
	return nil
}

func (r *Runner) heartbeat(ctx context.Context, st state.NodeState, stale bool) {
	hb := api.Heartbeat{
		AgentVersion: r.Version, AgentUptimeSec: int64(r.Now().Sub(r.started) / time.Second),
		AppliedConfigVersion: st.Applied.ConfigVersion, Stale: stale, Load1: readLoad1("/proc/loadavg"),
	}
	if err := r.API.Heartbeat(ctx, st.ServerID, hb); err != nil {
		r.failure("отправка heartbeat не удалась")
	}
}

func (r *Runner) failure(operation string) error {
	message := "узел: " + operation
	r.Log.Warn(message)
	return errors.New(message)
}

func (r *Runner) Run(ctx context.Context) error {
	wait := r.after
	if wait == nil {
		wait = time.After
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := r.Now()
		err := r.Step(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			r.failure("шаг завершился с ошибкой; цикл продолжится")
		}
		delay := max(time.Duration(0), r.delay()-r.Now().Sub(start))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait(delay):
		}
	}
}

func (r *Runner) delay() time.Duration {
	interval := r.Interval
	if interval <= 0 {
		interval = 25 * time.Second
	}
	span := interval / 10
	return interval - span + time.Duration(rand.Int64N(int64(2*span)+1))
}

func targetFrom(set api.DesiredSet, key wgtypes.Key) (wg.Target, error) {
	address, err := netip.ParsePrefix(set.TunnelAddress)
	if err != nil {
		return wg.Target{}, errors.New("узел: неверный адрес туннеля")
	}
	target := wg.Target{PrivateKey: key.String(), ListenPort: set.ListenPort, MTU: set.MTU, TunnelAddress: address, Peers: make([]wg.TargetPeer, 0, len(set.Peers))}
	for _, peer := range set.Peers {
		kind := wg.PeerKind(peer.State)
		if kind != wg.StateActive && kind != wg.StateRotatingOldKey {
			return wg.Target{}, errors.New("узел: неизвестное состояние пира")
		}
		p := wg.TargetPeer{PublicKey: peer.PublicKey, KeepaliveSec: set.KeepaliveSec, State: kind, AllowedIPs: make([]netip.Prefix, 0, len(peer.AllowedIPs))}
		for _, raw := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return wg.Target{}, errors.New("узел: неверный разрешённый адрес пира")
			}
			p.AllowedIPs = append(p.AllowedIPs, prefix)
		}
		target.Peers = append(target.Peers, p)
	}
	return target, nil
}

func report(version int64, live wg.LiveState) api.ObservedReport {
	out := api.ObservedReport{ConfigVersion: version, InterfaceRxBytes: live.IfaceRxBytes, InterfaceTxBytes: live.IfaceTxBytes, Peers: make([]api.ObservedPeer, 0, len(live.Peers))}
	for _, peer := range live.Peers {
		p := api.ObservedPeer{PublicKey: peer.PublicKey, RxBytes: peer.RxBytes, TxBytes: peer.TxBytes}
		if !peer.LastHandshake.IsZero() {
			utc := peer.LastHandshake.UTC()
			p.LatestHandshake = &utc
		}
		out.Peers = append(out.Peers, p)
	}
	slices.SortFunc(out.Peers, func(a, b api.ObservedPeer) int { return cmp.Compare(a.PublicKey, b.PublicKey) })
	return out
}

func readLoad1(path string) *float64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 5 {
		return nil
	}
	var loads [3]float64
	for i := range loads {
		load, err := strconv.ParseFloat(fields[i], 64)
		if err != nil || math.IsNaN(load) || math.IsInf(load, 0) || load < 0 {
			return nil
		}
		loads[i] = load
	}
	running, total, ok := strings.Cut(fields[3], "/")
	if !ok {
		return nil
	}
	for _, field := range []string{running, total, fields[4]} {
		if field == "" {
			return nil
		}
		for _, digit := range field {
			if digit < '0' || digit > '9' {
				return nil
			}
		}
	}
	return &loads[0]
}

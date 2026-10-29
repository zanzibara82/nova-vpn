package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/novavpn/novavpn/internal/nodeagent/api"
	"github.com/novavpn/novavpn/internal/nodeagent/state"
	"github.com/novavpn/novavpn/internal/nodeagent/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type desiredCall struct{ server, etag, token string }

type fixture struct {
	r                                                                                        Runner
	now                                                                                      time.Time
	st                                                                                       state.NodeState
	key                                                                                      wgtypes.Key
	set                                                                                      api.DesiredSet
	etag                                                                                     string
	notModified                                                                              bool
	before, snapshot                                                                         wg.LiveState
	rotated                                                                                  api.NodeToken
	activeToken                                                                              string
	trace                                                                                    []string
	requests                                                                                 []desiredCall
	targets                                                                                  []wg.Target
	reports                                                                                  []api.ObservedReport
	heartbeats                                                                               []api.Heartbeat
	saved                                                                                    []state.NodeState
	loadErr, keyErr, desiredErr, applyErr, snapshotErr, observedErr, heartbeatErr, rotateErr error
	saveHook                                                                                 func(state.NodeState) error
	desiredHook                                                                              func()
	logs                                                                                     bytes.Buffer
}

func generatedKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal("не удалось создать ключ теста")
	}
	return key
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.FixedZone("test", 3*3600)), key: generatedKey(t), etag: "etag-8"}
	f.st = state.NodeState{ServerID: "node-a", NodeToken: generatedKey(t).String(), TokenIssuedAt: f.now,
		Applied: state.Applied{ConfigVersion: 3, ETag: "disk-etag", AppliedAt: f.now.Add(-time.Hour), Peers: 2}}
	f.set = api.DesiredSet{ServerID: "node-a", ConfigVersion: 8, MTU: 1420, ListenPort: 51820, TunnelAddress: "10.99.0.1/24", KeepaliveSec: 25,
		Peers: []api.DesiredPeer{{PublicKey: generatedKey(t).PublicKey().String(), AllowedIPs: []string{"10.99.0.2/32", "fd00::2/128"}, State: "active"}}, MeasuredAt: f.now}
	f.before = wg.LiveState{IfaceRxBytes: 100, IfaceTxBytes: 200, Peers: map[string]wg.PeerState{
		"old-peer": {PublicKey: "old-peer", RxBytes: 11, TxBytes: 22, LastHandshake: f.now.Add(-time.Minute)},
	}}
	f.snapshot = wg.LiveState{IfaceRxBytes: 300, IfaceTxBytes: 400, Peers: map[string]wg.PeerState{
		"new-peer": {PublicKey: "new-peer", RxBytes: 33, TxBytes: 44},
	}}
	f.rotated = api.NodeToken{ServerID: "node-a", NodeToken: generatedKey(t).String()}
	f.r = Runner{API: f, Applier: f, Store: f, Iface: "wg0", Version: "test-version", Log: slog.New(slog.NewTextHandler(&f.logs, nil)), Now: func() time.Time { return f.now }}
	return f
}

func (f *fixture) Load() (state.NodeState, error) {
	f.trace = append(f.trace, "load")
	return f.st, f.loadErr
}
func (f *fixture) PrivateKey() (wgtypes.Key, error) {
	f.trace = append(f.trace, "key")
	return f.key, f.keyErr
}
func (f *fixture) Save(st state.NodeState) error {
	f.trace = append(f.trace, "save")
	f.saved = append(f.saved, st)
	if f.saveHook != nil {
		if err := f.saveHook(st); err != nil {
			return err
		}
	}
	f.st = st
	return nil
}
func (f *fixture) SetToken(token string) { f.trace = append(f.trace, "token"); f.activeToken = token }
func (f *fixture) Desired(_ context.Context, server, etag string) (api.DesiredSet, string, bool, error) {
	f.trace = append(f.trace, "desired")
	f.requests = append(f.requests, desiredCall{server, etag, f.activeToken})
	if f.desiredHook != nil {
		f.desiredHook()
	}
	return f.set, f.etag, f.notModified, f.desiredErr
}
func (f *fixture) Apply(target wg.Target) (wg.ApplyResult, error) {
	f.trace = append(f.trace, "apply")
	f.targets = append(f.targets, target)
	return wg.ApplyResult{Before: f.before, Ops: 2}, f.applyErr
}
func (f *fixture) Snapshot() (wg.LiveState, error) {
	f.trace = append(f.trace, "snapshot")
	return f.snapshot, f.snapshotErr
}
func (f *fixture) Observed(_ context.Context, server string, rep api.ObservedReport) error {
	f.trace = append(f.trace, "observed:"+server)
	f.reports = append(f.reports, rep)
	return f.observedErr
}
func (f *fixture) Heartbeat(_ context.Context, server string, hb api.Heartbeat) error {
	f.trace = append(f.trace, "heartbeat:"+server)
	f.heartbeats = append(f.heartbeats, hb)
	return f.heartbeatErr
}
func (f *fixture) RotateToken(_ context.Context, server string) (api.NodeToken, error) {
	f.trace = append(f.trace, "rotate:"+server)
	return f.rotated, f.rotateErr
}
func (f *fixture) stepOK(t *testing.T) {
	t.Helper()
	if err := f.r.Step(context.Background()); err != nil {
		t.Fatal("неожиданный отказ шага")
	}
}
func traceIs(t *testing.T, f *fixture, want string) {
	t.Helper()
	if strings.Join(f.trace, ",") != want {
		t.Fatalf("порядок операций: %s; ожидался %s", strings.Join(f.trace, ","), want)
	}
}
func heartbeatIs(t *testing.T, f *fixture, version int64, stale bool, uptime int64) {
	t.Helper()
	if len(f.heartbeats) == 0 {
		t.Fatal("heartbeat отсутствует")
	}
	hb := f.heartbeats[len(f.heartbeats)-1]
	if hb.AgentVersion != "test-version" || hb.AppliedConfigVersion != version || hb.Stale != stale || hb.AgentUptimeSec != uptime || hb.CPUPct != nil {
		t.Fatal("неверное содержимое heartbeat")
	}
	raw, err := json.Marshal(hb)
	if err != nil || !bytes.Contains(raw, []byte(`"cpu_pct":null`)) {
		t.Fatal("неизмеренная нагрузка CPU не равна null")
	}
}

var (
	_ API     = (*api.Client)(nil)
	_ Applier = (*wg.Applier)(nil)
	_ Store   = (*state.Store)(nil)
)

func TestStepAppliesFullSetAndReportsBefore(t *testing.T) {
	f := newFixture(t)
	originalToken := f.st.NodeToken
	f.stepOK(t)
	traceIs(t, f, "load,token,desired,key,apply,save,observed:node-a,heartbeat:node-a")
	if len(f.requests) != 1 || f.requests[0] != (desiredCall{"node-a", "", originalToken}) {
		t.Fatal("первый запрос должен использовать токен состояния без ETag")
	}
	wantTarget := wg.Target{PrivateKey: f.key.String(), ListenPort: 51820, MTU: 1420, TunnelAddress: netip.MustParsePrefix("10.99.0.1/24"),
		Peers: []wg.TargetPeer{{PublicKey: f.set.Peers[0].PublicKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32"), netip.MustParsePrefix("fd00::2/128")}, KeepaliveSec: 25, State: wg.StateActive}}}
	if len(f.targets) != 1 || !reflect.DeepEqual(f.targets[0], wantTarget) {
		t.Fatal("целевой набор передан неверно")
	}
	wantApplied := state.Applied{ConfigVersion: 8, ETag: "etag-8", AppliedAt: f.now.UTC(), Peers: 1}
	if f.st.Applied != wantApplied || !f.r.reconciled || f.st.NodeToken != originalToken {
		t.Fatal("применённое состояние не сохранено точно")
	}
	handshake := f.now.Add(-time.Minute).UTC()
	wantReport := api.ObservedReport{ConfigVersion: 8, InterfaceRxBytes: 100, InterfaceTxBytes: 200, Peers: []api.ObservedPeer{{PublicKey: "old-peer", RxBytes: 11, TxBytes: 22, LatestHandshake: &handshake}}}
	if len(f.reports) != 1 || !reflect.DeepEqual(f.reports[0], wantReport) {
		t.Fatal("отчёт должен содержать снимок до применения")
	}
	heartbeatIs(t, f, 8, false, 0)
	if !f.r.started.Equal(f.now) {
		t.Fatal("прямой Step не задал начало работы")
	}
	f.now = f.now.Add(25 * time.Second)
	f.stepOK(t)
	if f.requests[1].etag != "etag-8" {
		t.Fatal("повторный запрос потерял сохранённый ETag")
	}
	heartbeatIs(t, f, 8, false, 25)
}

func TestStepAcceptsEmptySetAndZeroVersion(t *testing.T) {
	f := newFixture(t)
	f.set.ConfigVersion = 0
	f.set.Peers = nil
	f.stepOK(t)
	if len(f.targets) != 1 || len(f.targets[0].Peers) != 0 || f.st.Applied.ConfigVersion != 0 || f.st.Applied.Peers != 0 || !f.r.reconciled {
		t.Fatal("пустой полный набор не применён")
	}
	heartbeatIs(t, f, 0, false, 0)
}

func TestStep304UsesFreshSnapshotWithoutApplying(t *testing.T) {
	f := newFixture(t)
	f.stepOK(t)
	st := f.st
	f.trace = nil
	f.notModified = true
	f.now = f.now.Add(25 * time.Second)
	f.stepOK(t)
	traceIs(t, f, "load,token,desired,snapshot,observed:node-a,heartbeat:node-a")
	want := api.ObservedReport{ConfigVersion: 8, InterfaceRxBytes: 300, InterfaceTxBytes: 400, Peers: []api.ObservedPeer{{PublicKey: "new-peer", RxBytes: 33, TxBytes: 44}}}
	if len(f.reports) != 2 || !reflect.DeepEqual(f.reports[1], want) || f.st != st || len(f.targets) != 1 || len(f.saved) != 1 {
		t.Fatal("304 изменил состояние или отправил старые счётчики")
	}
	heartbeatIs(t, f, 8, false, 25)
}

func TestStepRejectsUnconditional304(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold", true: "empty-etag"}[warm], func(t *testing.T) {
			f := newFixture(t)
			if warm {
				f.etag = ""
				f.stepOK(t)
				f.trace = nil
			}
			st := f.st
			f.notModified = true
			if f.r.Step(context.Background()) == nil {
				t.Fatal("безусловный 304 принят")
			}
			traceIs(t, f, "load,token,desired,heartbeat:node-a")
			if f.st != st || f.r.reconciled {
				t.Fatal("304 ошибочно подтвердил восстановление")
			}
			heartbeatIs(t, f, st.Applied.ConfigVersion, true, 0)
		})
	}
}

func TestStepSnapshotFailureDoesNotReportZeros(t *testing.T) {
	f := newFixture(t)
	f.stepOK(t)
	st := f.st
	f.trace = nil
	f.notModified = true
	f.snapshotErr = errors.New("snapshot failure")
	if f.r.Step(context.Background()) == nil {
		t.Fatal("отказ снимка скрыт")
	}
	traceIs(t, f, "load,token,desired,snapshot,heartbeat:node-a")
	if len(f.reports) != 1 || f.st != st {
		t.Fatal("отказ снимка изменил отчёт или состояние")
	}
	heartbeatIs(t, f, 8, false, 0)
}

func TestStepDesiredFailurePreservesStateAndSkipsRotation(t *testing.T) {
	for _, name := range []string{"unavailable", "unauthorized", "malformed", "incomplete"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.r.TokenTTL = time.Nanosecond
			f.st.TokenIssuedAt = f.now.Add(-time.Hour)
			f.desiredErr = errors.New(name)
			if name == "unauthorized" {
				f.desiredErr = &api.StatusError{Status: 401, Code: f.st.NodeToken}
			}
			st := f.st
			before := f.before
			f.stepOK(t)
			traceIs(t, f, "load,token,desired,heartbeat:node-a")
			if f.st != st || !reflect.DeepEqual(f.before, before) || f.r.reconciled {
				t.Fatal("отказ desired потерял последнее состояние")
			}
			heartbeatIs(t, f, 3, true, 0)
			if f.logs.Len() == 0 || strings.Contains(f.logs.String(), f.st.NodeToken) {
				t.Fatal("диагностика отсутствует или раскрывает токен")
			}
		})
	}
}

func TestStepRejectsForeignOrUnusableSet(t *testing.T) {
	for _, name := range []string{"foreign", "tunnel", "allowed", "state", "private-key"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			st := f.st
			switch name {
			case "foreign":
				f.set.ServerID = "another-node"
			case "tunnel":
				f.set.TunnelAddress = "invalid-tunnel"
			case "allowed":
				f.set.Peers[0].AllowedIPs = []string{"invalid-allowed"}
			case "state":
				f.set.Peers[0].State = "revoked"
			case "private-key":
				f.keyErr = errors.New("key failure")
			}
			if f.r.Step(context.Background()) == nil {
				t.Fatal("непригодный набор принят")
			}
			want := "load,token,desired,key,heartbeat:node-a"
			if name == "foreign" {
				want = "load,token,desired,heartbeat:node-a"
			}
			traceIs(t, f, want)
			if f.st != st || len(f.reports) != 0 || f.r.reconciled {
				t.Fatal("непригодный набор изменил Applied")
			}
			heartbeatIs(t, f, 3, true, 0)
		})
	}
}

func TestStepStopsOnLoadOrRegistrationFailure(t *testing.T) {
	for _, name := range []string{"load", "server", "token"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			switch name {
			case "load":
				f.loadErr = errors.New("load failure")
			case "server":
				f.st.ServerID = ""
			case "token":
				f.st.NodeToken = ""
			}
			if f.r.Step(context.Background()) == nil {
				t.Fatal("нет отказа состояния")
			}
			traceIs(t, f, "load")
		})
	}
}

func TestStepApplyFailureDoesNotAcknowledgeNewETag(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold", true: "warm"}[warm], func(t *testing.T) {
			f := newFixture(t)
			if warm {
				f.stepOK(t)
				f.trace = nil
			}
			st := f.st
			reports := len(f.reports)
			saves := len(f.saved)
			f.set.ConfigVersion = 9
			f.etag = "unapplied-etag"
			f.applyErr = errors.New("apply failure")
			f.stepOK(t)
			traceIs(t, f, "load,token,desired,key,apply,heartbeat:node-a")
			if f.st != st || len(f.reports) != reports || len(f.saved) != saves {
				t.Fatal("отказ применения подтверждён как успех")
			}
			heartbeatIs(t, f, st.Applied.ConfigVersion, false, 0)
			f.applyErr = nil
			f.stepOK(t)
			want := ""
			if warm {
				want = "etag-8"
			}
			if f.requests[len(f.requests)-1].etag != want {
				t.Fatal("запрошен ETag неприменённого набора")
			}
		})
	}
}

func TestStepAppliedSaveFailureForcesFullRetry(t *testing.T) {
	f := newFixture(t)
	f.stepOK(t)
	st := f.st
	f.trace = nil
	f.set.ConfigVersion = 9
	f.etag = "etag-9"
	f.saveHook = func(state.NodeState) error { return errors.New("save failure") }
	if f.r.Step(context.Background()) == nil {
		t.Fatal("отказ записи скрыт")
	}
	traceIs(t, f, "load,token,desired,key,apply,save")
	if f.st != st || f.r.reconciled || len(f.reports) != 1 || len(f.heartbeats) != 1 {
		t.Fatal("несохранённый набор подтверждён")
	}
	f.saveHook = nil
	f.stepOK(t)
	if f.requests[2].etag != "" || f.st.Applied.ConfigVersion != 9 {
		t.Fatal("после отказа записи не запрошен полный набор")
	}
}

func TestStepReportingFailuresDoNotBlockHeartbeatOrRotation(t *testing.T) {
	for _, name := range []string{"observed", "heartbeat", "both"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.st.TokenIssuedAt = f.now.Add(-24 * time.Hour)
			if name != "heartbeat" {
				f.observedErr = errors.New("observed failure")
			}
			if name != "observed" {
				f.heartbeatErr = errors.New("heartbeat failure")
			}
			f.stepOK(t)
			traceIs(t, f, "load,token,desired,key,apply,save,observed:node-a,heartbeat:node-a,rotate:node-a,token,save")
			if f.st.Applied.ConfigVersion != 8 || f.st.NodeToken != f.rotated.NodeToken || f.logs.Len() == 0 {
				t.Fatal("отказ отчёта помешал успешному циклу")
			}
			heartbeatIs(t, f, 8, false, 0)
		})
	}
}

func TestTokenRotationThresholdAndNextDesiredToken(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ttl, age time.Duration
		rotate   bool
	}{
		{"before", time.Hour, time.Hour - time.Nanosecond, false}, {"equal", time.Hour, time.Hour, true}, {"after", time.Hour, time.Hour + time.Nanosecond, true},
		{"default-zero-before", 0, 24*time.Hour - time.Nanosecond, false}, {"default-zero-equal", 0, 24 * time.Hour, true}, {"default-negative", -1, 24 * time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.r.TokenTTL = tc.ttl
			f.st.TokenIssuedAt = f.now.Add(-tc.age)
			old := f.st
			f.stepOK(t)
			if slices.Contains(f.trace, "rotate:node-a") != tc.rotate {
				t.Fatal("неверная граница ротации")
			}
			wantToken := old.NodeToken
			wantIssued := old.TokenIssuedAt
			if tc.rotate {
				wantToken = f.rotated.NodeToken
				wantIssued = f.now.UTC()
			}
			if f.st.NodeToken != wantToken || f.st.TokenIssuedAt != wantIssued || f.activeToken != wantToken {
				t.Fatal("токен или время выдачи не обновлены")
			}
			f.notModified = true
			f.trace = nil
			f.stepOK(t)
			if f.requests[1].token != wantToken || slices.Contains(f.trace, "rotate:node-a") {
				t.Fatal("следующий desired не использовал актуальный токен")
			}
		})
	}
}

func TestTokenRotationOn304(t *testing.T) {
	f := newFixture(t)
	f.stepOK(t)
	f.now = f.now.Add(24 * time.Hour)
	f.notModified = true
	f.trace = nil
	f.stepOK(t)
	traceIs(t, f, "load,token,desired,snapshot,observed:node-a,heartbeat:node-a,rotate:node-a,token,save")
	if f.st.NodeToken != f.rotated.NodeToken || f.st.TokenIssuedAt != f.now.UTC() {
		t.Fatal("304 не сохранил новый токен")
	}
}

func TestTokenRotationRejectsAPIErrorAndInvalidResponses(t *testing.T) {
	for _, name := range []string{"api", "empty", "foreign"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.st.TokenIssuedAt = f.now.Add(-24 * time.Hour)
			old := f.st
			switch name {
			case "api":
				f.rotateErr = errors.New("rotate failure")
			case "empty":
				f.rotated.NodeToken = ""
			case "foreign":
				f.rotated.ServerID = "another-node"
			}
			if f.r.Step(context.Background()) == nil {
				t.Fatal("отказ ротации скрыт")
			}
			traceIs(t, f, "load,token,desired,key,apply,save,observed:node-a,heartbeat:node-a,rotate:node-a")
			if f.st.NodeToken != old.NodeToken || f.st.TokenIssuedAt != old.TokenIssuedAt || f.activeToken != old.NodeToken || f.r.pendingState != nil {
				t.Fatal("неверный ответ активировал токен")
			}
		})
	}
}

func TestTokenSaveRetryPrecedesAnyHTTPAndNeverReloadsOldToken(t *testing.T) {
	f := newFixture(t)
	f.st.TokenIssuedAt = f.now.Add(-24 * time.Hour)
	oldToken := f.st.NodeToken
	f.saveHook = func(st state.NodeState) error {
		if st.NodeToken == f.rotated.NodeToken {
			if f.activeToken != f.rotated.NodeToken {
				t.Fatal("новый токен не активирован до записи")
			}
			return errors.New("token save failure")
		}
		return nil
	}
	if f.r.Step(context.Background()) == nil {
		t.Fatal("отказ записи токена скрыт")
	}
	if f.r.pendingState == nil || f.r.pendingState.NodeToken != f.rotated.NodeToken || f.r.pendingState.TokenIssuedAt != f.now.UTC() || f.activeToken != f.rotated.NodeToken || f.st.NodeToken != oldToken {
		t.Fatal("выданный токен не удержан в памяти")
	}
	pending := *f.r.pendingState
	f.trace = nil
	if f.r.Step(context.Background()) == nil {
		t.Fatal("повторный отказ записи скрыт")
	}
	traceIs(t, f, "save")
	if *f.r.pendingState != pending || f.activeToken != f.rotated.NodeToken {
		t.Fatal("повтор записи потерял новый токен")
	}
	f.saveHook = nil
	f.trace = nil
	f.notModified = true
	f.stepOK(t)
	traceIs(t, f, "save,load,token,desired,snapshot,observed:node-a,heartbeat:node-a")
	if f.r.pendingState != nil || f.st != pending || f.requests[1].token != f.rotated.NodeToken {
		t.Fatal("восстановление использовало старый токен или потеряло состояние")
	}
}

func TestTargetFromPreservesHostAndPeerStates(t *testing.T) {
	f := newFixture(t)
	f.set.Peers = append(f.set.Peers, api.DesiredPeer{PublicKey: "old-public", AllowedIPs: []string{"10.99.0.3/32"}, State: "rotating_old_key"})
	target, err := targetFrom(f.set, f.key)
	if err != nil {
		t.Fatal("валидный набор отвергнут")
	}
	if target.TunnelAddress.String() != "10.99.0.1/24" || target.PrivateKey != f.key.String() || target.MTU != 1420 || target.ListenPort != 51820 || len(target.Peers) != 2 {
		t.Fatal("параметры цели искажены")
	}
	if target.Peers[0].State != wg.StateActive || target.Peers[1].State != wg.StateRotatingOldKey || target.Peers[1].PublicKey != "old-public" || target.Peers[1].KeepaliveSec != 25 || target.Peers[1].AllowedIPs[0].String() != "10.99.0.3/32" {
		t.Fatal("состояния пиеров или их поля потеряны")
	}
	if !reflect.DeepEqual(target.Peers[0].AllowedIPs, []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32"), netip.MustParsePrefix("fd00::2/128")}) {
		t.Fatal("список адресов потерян")
	}
}

func TestTargetFromErrorsDoNotQuoteInput(t *testing.T) {
	for _, name := range []string{"tunnel", "allowed", "state"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			input := f.st.NodeToken
			switch name {
			case "tunnel":
				f.set.TunnelAddress = input
			case "allowed":
				f.set.Peers[0].AllowedIPs = []string{input}
			case "state":
				f.set.Peers[0].State = input
			}
			_, err := targetFrom(f.set, f.key)
			if err == nil || strings.Contains(err.Error(), input) || strings.Contains(err.Error(), f.key.String()) {
				t.Fatal("ошибка преобразования отсутствует или раскрывает вход")
			}
		})
	}
}

func TestReportSortsCountersAndEncodesUnknownHandshake(t *testing.T) {
	handshake := time.Date(2026, 10, 27, 12, 0, 0, 0, time.FixedZone("test", 3600))
	live := wg.LiveState{IfaceRxBytes: 101, IfaceTxBytes: 202, Peers: map[string]wg.PeerState{
		"map-first": {PublicKey: "z", RxBytes: 31, TxBytes: 41, LastHandshake: handshake},
		"map-last":  {PublicKey: "a", RxBytes: 51, TxBytes: 61},
	}}
	rep := report(17, live)
	utc := handshake.UTC()
	want := api.ObservedReport{ConfigVersion: 17, InterfaceRxBytes: 101, InterfaceTxBytes: 202, Peers: []api.ObservedPeer{{PublicKey: "a", RxBytes: 51, TxBytes: 61}, {PublicKey: "z", RxBytes: 31, TxBytes: 41, LatestHandshake: &utc}}}
	if !reflect.DeepEqual(rep, want) || rep.Peers[1].LatestHandshake.Location() != time.UTC {
		t.Fatal("сортировка, счётчики или UTC неверны")
	}
	raw, err := json.Marshal(rep)
	if err != nil || !bytes.Contains(raw, []byte(`"latest_handshake":null`)) {
		t.Fatal("отсутствующий handshake не равен null")
	}
	raw, err = json.Marshal(report(0, wg.LiveState{}))
	if err != nil || !bytes.Contains(raw, []byte(`"peers":[]`)) {
		t.Fatal("пустой список пиеров не равен []")
	}
}

func TestHeartbeatUsesActualProcLoad(t *testing.T) {
	read := func() float64 {
		raw, err := os.ReadFile("/proc/loadavg")
		if err != nil || len(strings.Fields(string(raw))) == 0 {
			t.Fatal("для этого теста требуется Linux с /proc/loadavg")
		}
		v, err := strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
		if err != nil {
			t.Fatal("не удалось прочитать нагрузку Linux")
		}
		return v
	}
	f := newFixture(t)
	before := read()
	f.stepOK(t)
	after := read()
	load := f.heartbeats[0].Load1
	if load == nil || (*load != before && *load != after) {
		t.Fatal("heartbeat не содержит фактический замер нагрузки")
	}
}

func TestReadLoad1FromFiles(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		valid         bool
		want          float64
	}{
		{"valid", "0.75 0.40 0.20 1/123 42\n", true, 0.75}, {"zero", "0 0 0 1/2 3", true, 0},
		{"empty", "", false, 0}, {"broken", "broken 1 2", false, 0}, {"nan", "NaN 1 2", false, 0},
		{"inf", "+Inf 1 2", false, 0}, {"negative", "-0.1 1 2", false, 0}, {"missing", "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "loadavg")
			if tc.name != "missing" {
				if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
					t.Fatal("не удалось записать файл теста")
				}
			}
			got := readLoad1(path)
			if tc.valid {
				if got == nil || *got != tc.want {
					t.Fatal("нагрузка прочитана неверно")
				}
			} else if got != nil {
				t.Fatal("неизмеренная нагрузка не равна nil")
			}
		})
	}
}

func TestStepHonorsCancellationBeforeAllWork(t *testing.T) {
	f := newFixture(t)
	pending := f.st
	f.r.pendingState = &pending
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(f.r.Step(ctx), context.Canceled) || len(f.trace) != 0 || !f.r.started.IsZero() {
		t.Fatal("отменённый Step начал работу")
	}
}

func TestRunHonorsCancellationBeforeStepAndDuringWait(t *testing.T) {
	for _, early := range []bool{true, false} {
		t.Run(map[bool]string{true: "before", false: "wait"}[early], func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waits := 0
			f.r.after = func(time.Duration) <-chan time.Time { waits++; cancel(); return make(chan time.Time) }
			if early {
				cancel()
			}
			if !errors.Is(f.r.Run(ctx), context.Canceled) {
				t.Fatal("Run не вернул отмену")
			}
			want := 1
			if early {
				want = 0
			}
			if len(f.requests) != want || waits != want {
				t.Fatal("Run нарушил отмену или не начал первый шаг сразу")
			}
		})
	}
}

func TestRunContinuesAfterErrorAndSubtractsStepDuration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		elapsed  time.Duration
		min, max time.Duration
	}{
		{"short", 4 * time.Second, 18500 * time.Millisecond, 23500 * time.Millisecond}, {"long", time.Minute, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.keyErr = errors.New("key failure")
			waits := 0
			busy := false
			f.desiredHook = func() {
				if busy || len(f.requests) != waits+1 {
					t.Fatal("шаги перекрываются или выполняются без ожидания")
				}
				busy = true
				f.now = f.now.Add(tc.elapsed)
				busy = false
			}
			f.r.after = func(delay time.Duration) <-chan time.Time {
				if busy || len(f.requests) != waits+1 || delay < tc.min || delay > tc.max {
					t.Fatal("ожидание не компенсирует длительность шага")
				}
				waits++
				f.now = f.now.Add(delay)
				f.keyErr = nil
				if waits == 2 {
					cancel()
				}
				ch := make(chan time.Time, 1)
				ch <- f.now
				return ch
			}
			if !errors.Is(f.r.Run(ctx), context.Canceled) || waits != 2 || len(f.requests) != 2 || len(f.targets) != 1 || f.st.Applied.ConfigVersion != 8 || f.logs.Len() == 0 {
				t.Fatal("Run остановился после отказа или не восстановился")
			}
		})
	}
}

func TestDelayBoundsAndTinyIntervals(t *testing.T) {
	for _, tc := range []struct {
		name               string
		interval, min, max time.Duration
	}{
		{"zero", 0, 22500 * time.Millisecond, 27500 * time.Millisecond}, {"negative", -time.Second, 22500 * time.Millisecond, 27500 * time.Millisecond},
		{"positive", time.Second, 900 * time.Millisecond, 1100 * time.Millisecond}, {"tiny", time.Nanosecond, time.Nanosecond, time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Runner{Interval: tc.interval}
			for i := 0; i < 1000; i++ {
				d := r.delay()
				if d < tc.min || d > tc.max {
					t.Fatal("jitter вышел за границы")
				}
			}
		})
	}
}

func TestRunnerLogsNeverIncludeDependencySecrets(t *testing.T) {
	for _, name := range []string{"load", "key", "desired", "status", "apply", "snapshot", "save", "observed", "heartbeat", "rotate", "run"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			secret := f.st.NodeToken
			private := f.key.String()
			bad := errors.New(secret + " " + private)
			switch name {
			case "load", "run":
				f.loadErr = bad
			case "key":
				f.keyErr = bad
			case "desired":
				f.desiredErr = bad
			case "status":
				f.desiredErr = &api.StatusError{Status: 401, Code: secret + private}
			case "apply":
				f.applyErr = bad
			case "snapshot":
				f.stepOK(t)
				f.notModified = true
				f.snapshotErr = bad
			case "save":
				f.saveHook = func(state.NodeState) error { return bad }
			case "observed":
				f.observedErr = bad
			case "heartbeat":
				f.heartbeatErr = bad
			case "rotate":
				f.st.TokenIssuedAt = f.now.Add(-24 * time.Hour)
				f.rotateErr = bad
			}
			if name == "run" {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.r.after = func(time.Duration) <-chan time.Time { cancel(); return make(chan time.Time) }
				_ = f.r.Run(ctx)
			} else {
				_ = f.r.Step(context.Background())
			}
			text := f.logs.String()
			if text == "" || strings.Contains(text, secret) || strings.Contains(text, private) {
				t.Fatal("журнал пуст или содержит секрет зависимости")
			}
		})
	}
}

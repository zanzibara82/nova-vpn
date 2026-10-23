//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

func newDeviceSvc(t *testing.T) (*devices.Service, *db.Queries) {
	t.Helper()
	q := db.New(pool(t))
	return devices.NewService(pool(t), entitlements.New(q)), q
}

func keyAt(i int) string {
	// Ключ собирается из 32 raw-байт, а не правкой готовой строки. Причина ровно та
	// же, из-за которой валидатор задачи 14 существует: у 44-символьного base64
	// последнего символа два младших бита — spare, и в канонической кодировке они
	// нулевые. «Поменять букву» в строке — способ получить неканонический ключ,
	// который Register отклонит 400 вместо ожидаемого 201 или 409.
	raw := make([]byte, 32)
	copy(raw, "novavpn-integration-key-")
	raw[30], raw[31] = byte(i>>8), byte(i)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestDeviceLimitIsHard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	svc, q := newDeviceSvc(t)
	user := seedUser(t, ctx, q, true) // подписка internal-default, device_limit = 3

	for i := 0; i < 3; i++ {
		if _, err := svc.Register(ctx, user, devices.RegisterInput{
			PublicKey: keyAt(i), Platform: "linux", Name: "dev"}); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	_, err := svc.Register(ctx, user, devices.RegisterInput{
		PublicKey: keyAt(3), Platform: "linux", Name: "fourth"})
	if err == nil || !errors.Is(err, devices.ErrDeviceLimit) {
		t.Fatalf("4th device: err = %v, want ErrDeviceLimit", err)
	}

	// Тот же публичный ключ второй раз → duplicate, а не «тихо вернули первое устройство».
	if _, err := svc.Register(ctx, user, devices.RegisterInput{
		PublicKey: keyAt(0), Platform: "linux", Name: "dup"}); !errors.Is(err, devices.ErrDuplicateKey) {
		t.Errorf("duplicate key: err = %v, want ErrDuplicateKey", err)
	}

	// Чужое устройство недоступно по ID.
	other := seedUser(t, ctx, q, true)
	list, err := svc.List(ctx, other)
	if err != nil || len(list) != 0 {
		t.Errorf("other user sees %d devices (err=%v)", len(list), err)
	}
	if _, err := svc.OwnedBy(ctx, list0ID(t, ctx, user), other); !errors.Is(err, devices.ErrForbiddenDevice) {
		t.Errorf("OwnedBy cross-user = %v, want ErrForbiddenDevice", err)
	}
}

func list0ID(t *testing.T, ctx context.Context, user uuid.UUID) uuid.UUID {
	t.Helper()
	svc, _ := newDeviceSvc(t)
	list, err := svc.List(ctx, user)
	if err != nil || len(list) == 0 {
		t.Fatalf("no devices to reference: %v", err)
	}
	return list[0].ID
}

// Гонка на лимит: advisory lock в транзакции обязан не пустить четвёртого,
// сколько горутин ни пришло одновременно.
func TestConcurrentRegistrationRespectsLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	svc, q := newDeviceSvc(t)
	user := seedUser(t, ctx, q, true)

	var wg sync.WaitGroup
	var mu sync.Mutex
	limiterHits := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.Register(ctx, user, devices.RegisterInput{
				PublicKey: keyAt(100 + i), Platform: "linux", Name: "race"})
			if errors.Is(err, devices.ErrDeviceLimit) {
				mu.Lock()
				limiterHits++
				mu.Unlock()
				return
			}
			if err != nil {
				t.Errorf("register %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	live, err := db.New(pool(t)).CountLiveDevices(ctx, user)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if live != 3 {
		t.Errorf("live devices = %d, want exactly 3 (limit 3, 10 concurrent attempts)", live)
	}
	if limiterHits != 7 {
		t.Errorf("ErrDeviceLimit hits = %d, want 7", limiterHits)
	}
}

func TestHandlerMapsErrorsToCodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	svc, q := newDeviceSvc(t)
	user := seedUser(t, ctx, q, true)
	// dec здесь — сквозные обёртки: тест проверяет маппинг ошибок хендлера,
	// а не аутентификацию и не лимиты (они — в задачах 17 и 18).
	passthrough := func(next http.Handler) http.Handler { return next }
	dec := httpx.Decorators{Auth: passthrough, Anonymous: passthrough}
	mux := http.NewServeMux()
	devices.NewHandler(svc, nil).RegisterRoutes(mux, dec)
	var h http.Handler = mux
	post := func(body string, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		req = req.Clone(httpx.WithUserID(req.Context(), user))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	w := post(`{"public_key":"`+keyAt(0)+`","platform":"linux","name":"laptop"}`, uuid.NewString())
	if w.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", w.Code, w.Body)
	}
	// Невалидный ключ → 400 invalid_request с полем в details.
	w = post(`{"public_key":"not-a-key","platform":"linux","name":"x"}`, uuid.NewString())
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"public_key"`) {
		t.Fatalf("bad key: %d %s", w.Code, w.Body)
	}
	// Неизвестная платформа → 400.
	w = post(`{"public_key":"`+keyAt(1)+`","platform":"toaster","name":"x"}`, uuid.NewString())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad platform: %d %s", w.Code, w.Body)
	}
	// Отсутствие Idempotency-Key на POST /devices → 400 (спецификация §5.2).
	w = post(`{"public_key":"`+keyAt(2)+`","platform":"linux","name":"x"}`, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"idempotency_key_required"`) {
		t.Fatalf("missing idempotency key: %d %s", w.Code, w.Body)
	}
}

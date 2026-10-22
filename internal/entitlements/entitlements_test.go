package entitlements

import (
	"testing"

	"github.com/google/uuid"
)

func TestAllowsDeviceCountsAgainstLimit(t *testing.T) {
	e := Entitlement{PlanID: uuid.New(), Slug: "internal-default", DeviceLimit: 3, ServerSelector: "all"}
	for live, want := range map[int]bool{0: true, 2: true, 3: false, 4: false} {
		if got := e.AllowsDevice(live); got != want {
			t.Errorf("AllowsDevice(%d) = %v, want %v", live, got, want)
		}
	}
}

// Нулевой лимит — сломанные данные, а не «неограниченно»: тихое «всем можно» здесь
// хуже отказа.
func TestZeroDeviceLimitIsRejected(t *testing.T) {
	if _, err := normalize(Entitlement{DeviceLimit: 0, ServerSelector: "all"}); err == nil {
		t.Fatal("device_limit = 0 accepted")
	}
	if _, err := normalize(Entitlement{DeviceLimit: 3, ServerSelector: "nonsense"}); err == nil {
		t.Fatal("unknown server_selector accepted")
	}
}

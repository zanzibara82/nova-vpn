package connections

import (
	"testing"
	"time"

	"github.com/novavpn/novavpn/internal/entitlements"
)

func TestProfileExpiry(t *testing.T) {
	// now фиксирован: сравнение с time.Now().Add(...) зависело бы от того, сколько
	// процессор потратил секунд между двумя вызовами, и редкий прогон падал бы на
	// наносекундах, а не на правиле.
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	endsIn := func(d time.Duration) *time.Time {
		v := now.Add(d)
		return &v
	}
	const thirtyDays = 30 * 24 * time.Hour

	cases := []struct {
		name string
		ent  entitlements.Entitlement
		want time.Time
	}{
		{
			name: "бессрочная подписка — потолок плана",
			ent:  entitlements.Entitlement{},
			want: now.Add(thirtyDays),
		},
		{
			name: "подписка кончается раньше потолка — срок по подписке",
			ent:  entitlements.Entitlement{EndsAt: endsIn(2 * 24 * time.Hour)},
			want: now.Add(2 * 24 * time.Hour),
		},
		{
			name: "подписка дольше потолка — потолок важнее",
			ent:  entitlements.Entitlement{EndsAt: endsIn(60 * 24 * time.Hour)},
			want: now.Add(thirtyDays),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ProfileExpiry(c.ent, now)
			if !got.Equal(c.want) {
				t.Errorf("срок = %v, want %v", got, c.want)
			}
		})
	}
	// Потолок назван числом, а не константой, ровно для этого утверждения: если
	// DefaultProfileTTL перепишут, тест обязан заметить, что обещанные тридцать
	// суток превратились в другое число.
	if DefaultProfileTTL != thirtyDays {
		t.Errorf("DefaultProfileTTL = %v, want %v", DefaultProfileTTL, thirtyDays)
	}
}

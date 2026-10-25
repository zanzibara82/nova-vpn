package audit

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

func TestCheckAction(t *testing.T) {
	ok := Action{AdminID: uuid.New(), Action: db.AuditActionServerCreated,
		TargetType: "server", TargetID: uuid.NewString(),
		Reason: "узел переведён в draining", RequestID: "0000deadbeef0000"}
	if err := check(ok); err != nil {
		t.Fatalf("valid action rejected: %v", err)
	}
	// rune-счёт, не байтовый: три кириллических символа — 6 байт, и отказывать им нельзя.
	short := ok
	short.Reason = "да"
	if err := check(short); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("short reason: err = %v, want ErrReasonRequired", err)
	}
	long := ok
	long.Reason = strings.Repeat("п", maxReason+1)
	if err := check(long); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("long reason: err = %v, want ErrReasonRequired", err)
	}
	noSubject := ok
	noSubject.AdminID = uuid.Nil
	if err := check(noSubject); err == nil {
		t.Error("action without subject accepted")
	}
	noTarget := ok
	noTarget.TargetID = ""
	if err := check(noTarget); err == nil {
		t.Error("action without target accepted")
	}
}

package httpx

import (
	"context"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

type PGIdempotency struct{ q *db.Queries }

func NewPGIdempotency(pool db.DBTX) *PGIdempotency { return &PGIdempotency{q: db.New(pool)} }

func (p *PGIdempotency) Claim(ctx context.Context, userID uuid.UUID, route, key string, hash []byte) (db.IdempotencyKey, bool, error) {
	inserted, err := p.q.ClaimIdempotencyKey(ctx, db.ClaimIdempotencyKeyParams{
		ID: uuid.New(), UserID: userID, Route: route, IdemKey: key, RequestHash: hash,
	})
	if err != nil {
		return db.IdempotencyKey{}, false, err
	}
	if inserted == 1 {
		// ON CONFLICT DO NOTHING: строка вставлена → повтор не найден → слот наш.
		return db.IdempotencyKey{}, false, nil
	}
	existing, err := p.q.LoadIdempotencyKey(ctx, db.LoadIdempotencyKeyParams{
		UserID: userID, Route: route, IdemKey: key,
	})
	if err != nil {
		return db.IdempotencyKey{}, false, err
	}
	return existing, true, nil
}

func (p *PGIdempotency) Complete(ctx context.Context, userID uuid.UUID, route, key string, status int, body []byte) error {
	statusCode := int32(status)
	return p.q.CompleteIdempotencyKey(ctx, db.CompleteIdempotencyKeyParams{
		UserID: userID, Route: route, IdemKey: key, ResponseStatus: &statusCode, ResponseBody: body,
	})
}

func (p *PGIdempotency) Abandon(ctx context.Context, userID uuid.UUID, route, key string) error {
	return p.q.DeleteIdempotencyKey(ctx, db.DeleteIdempotencyKeyParams{
		UserID: userID, Route: route, IdemKey: key,
	})
}

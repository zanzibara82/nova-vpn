package httpx

import (
	"context"

	"github.com/google/uuid"
)

type userIDKey struct{}

func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	// Журналу нужен сам субъект, а не новый контекст: аккумулятор живёт в
	// предыдущем ctx и доступен по указателю.
	noteUserID(ctx, id)
	return context.WithValue(ctx, userIDKey{}, id)
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey{}).(uuid.UUID)
	return id, ok
}

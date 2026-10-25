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

type serverIDKey struct{}

// WithServerID — то же, что WithUserID, только для узла: у запроса из
// /internal/v1 субъект — сервер, а не человек. Нужен двум читателям: журналу
// (какой узел стучался) и лимитеру (ключ бакета «на узел», а не «на путь»).
func WithServerID(ctx context.Context, id uuid.UUID) context.Context {
	noteServerID(ctx, id)
	return context.WithValue(ctx, serverIDKey{}, id)
}

func ServerIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(serverIDKey{}).(uuid.UUID)
	return id, ok
}

type adminIDKey struct{}

// WithAdminID — копия пары WithUserID с собственным ключом. «Универсальный» ключ
// субъекта здесь запрещён намеренно: админ — не «пользователь с другим id», а другой
// класс доступа (другой iss, другой бакет лимитера, право на чужие данные), и опечатка
// в хендлере, прочитавшая id админа как id пользователя, с общим ключом была бы
// неотличима от исправного кода.
func WithAdminID(ctx context.Context, id uuid.UUID) context.Context {
	noteAdminID(ctx, id)
	return context.WithValue(ctx, adminIDKey{}, id)
}

func AdminIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(adminIDKey{}).(uuid.UUID)
	return id, ok
}

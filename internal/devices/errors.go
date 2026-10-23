package devices

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// devices_user_key приходит как 23505. Это единственный уникальный индекс, в который
// может упереться вставка устройства, поэтому различать имена ограничений нечем —
// текст PgError.Constraint оставляем в логе, коду ошибки он не соответствует.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

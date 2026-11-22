package admin

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsUniqueViolationUsesConstraintName(t *testing.T) {
	const loc = "server_locations_country_code_city_lat_lon_key"
	unique := &pgconn.PgError{
		Code:           "23505",
		Message:        fmt.Sprintf(`duplicate key value violates unique constraint %q`, loc),
		ConstraintName: loc,
	}
	cases := []struct {
		name       string
		err        error
		constraint string
		want       bool
	}{
		{"имя совпало", unique, loc, true},
		{"имя совпало во wrapped-ошибке", fmt.Errorf("insert location: %w", unique), loc, true},
		{"любое уникальное при пустом имени", unique, "", true},
		{"чужое имя", unique, "users_email_key", false},
		{"не уникальное нарушение", &pgconn.PgError{Code: "23503", ConstraintName: loc}, loc, false},
		{"не ошибка PostgreSQL", errors.New("duplicate key value violates unique constraint"), loc, false},
	}
	for _, c := range cases {
		if got := isUniqueViolation(c.err, c.constraint); got != c.want {
			t.Errorf("%s: isUniqueViolation = %v, want %v", c.name, got, c.want)
		}
	}
}

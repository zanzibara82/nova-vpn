// Package migrations держит SQL-артефакты рядом с бинарником: миграции применяются
// из embedded FS, поэтому и в контейнере, и в CI нужен один и тот же артефакт сборки.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS

package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/novavpn/novavpn/migrations"
)

func open(ctx context.Context, url string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("migration source: %w", err)
	}
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("postgres handle: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	// WithInstance, а не Open(url): golang-migrate ожидает драйвер с именем
	// "postgres" (lib/pq), а pgx/v5/stdlib регистрируется как "pgx".
	driver, err := migratepg.WithInstance(sqlDB, &migratepg.Config{})
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("postgres driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return m, nil
}

// Up применяет все недостающие миграции и возвращает итоговую версию.
func Up(ctx context.Context, url string) (uint, error) {
	m, err := open(ctx, url)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return 0, err
	}
	return version(m)
}

// Steps делает n шагов: отрицательное n откатывает (n = -1<<31 — до чистой базы).
func Steps(ctx context.Context, url string, n int) (uint, error) {
	m, err := open(ctx, url)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	if n < 0 {
		// На чистой базе откатывать нечего, а golang-migrate при шаге вниз читает
		// down-файл версии 0 и возвращает fs.ErrNotExist («file does not exist»),
		// а не ErrNoChange. Проверено на postgres:17 с пустой schema_migrations.
		if _, _, verr := m.Version(); errors.Is(verr, migrate.ErrNilVersion) {
			return 0, nil
		}
	}
	if err := m.Steps(n); err != nil && !errors.Is(err, migrate.ErrNoChange) && !isLimit(err) {
		return 0, err
	}
	return version(m)
}

// isLimit — «шагов запрошено больше, чем есть файлов». О значении судят по обоим
// концам цепочки: n = -1<<31 означает «до нуля» и упирается в этот случай штатно
// (проверено: `migrate all` на версии 3 давал «limit 2147483645 short» с кодом 1).
// Поэтому он не ошибка, а достигнутый конец схемы.
func isLimit(err error) bool {
	var short migrate.ErrShortLimit
	return errors.As(err, &short)
}

func version(m *migrate.Migrate) (uint, error) {
	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		// Схема без единой миграции — это версия 0, а не ошибка.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if dirty {
		return v, fmt.Errorf("schema is dirty at version %d", v)
	}
	return v, nil
}

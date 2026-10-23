// Package servers отдаёт каталог серверов и решает, что считать сервер доступным.
// Здесь нет ни аллокации адресов, ни выдачи профилей: только чтение того, что
// вывел в online оператор, и честная оценка свежести heartbeat'а.
package servers

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/novavpn/novavpn/internal/db"
)

// Availability — ответ каталога о том, стоит ли предлагать этот сервер клиенту.
type Availability string

const (
	AvailabilityAvailable Availability = "available"
	AvailabilityUnknown   Availability = "unknown"
)

// DefaultStaleAfter — окно, за которым heartbeat считается потерян: три интервала
// опроса по 30 с (§4.3). Своего sweeper у этого окна нет (задача 13 переводит
// узел в 'stale' тем же порогом), поэтому каталог и БД судят об одном и том же
// возрасте одним числом.
const DefaultStaleAfter = 90 * time.Second

// Available — чистая функция: доступным сервер может быть только тогда, когда
// узел сам сказал, что жив, и сказал это недавно. Значения «unavailable» нет
// сознательно: в каталог попадает только maintenance_status='online', а всё
// остальное для нас «неизвестно», потому что API не измерял связность (§1.2) и
// выдавать «недоступен» было бы утверждением о том, чего мы не проверяли.
func Available(status *string, observedAt *time.Time, now time.Time) Availability {
	if status == nil || observedAt == nil {
		return AvailabilityUnknown
	}
	if *status != string(db.HealthStatusOk) {
		return AvailabilityUnknown
	}
	age := now.Sub(*observedAt)
	if age > DefaultStaleAfter || age < 0 {
		return AvailabilityUnknown
	}
	return AvailabilityAvailable
}

// Summary — один сервер каталога. LatencyMS и Load всегда nil: это не забытые
// поля, а обещание (§13.4, ADR-006) — контрол-плейн не измерял задержку и
// загрузку, и нуль или «правдоподобное число» здесь были бы подменой.
type Summary struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	CountryCode  string       `json:"country_code"`
	City         string       `json:"city"`
	Host         string       `json:"host"`
	Port         int          `json:"port"`
	MTU          int          `json:"mtu"`
	Latitude     float64      `json:"latitude"`
	Longitude    float64      `json:"longitude"`
	Availability Availability `json:"availability"`
	LatencyMS    *int64       `json:"latency_ms"`
	Load         *float64     `json:"load"`
	CapacityMbps *int32       `json:"capacity_mbps"`
	Provider     string       `json:"provider"`
	Region       string       `json:"region"`
}

type Service struct {
	q *db.Queries
}

func NewService(q *db.Queries) *Service { return &Service{q: q} }

// Catalog читает выведенные серверы и собирает ответ. Ошибка парсинга координат
// прерывает весь ответ: тихий ноль в широте был бы ровно той подменой, которую
// запрещает ТЗ §19.3, а клиент по такой координате показал бы сервер в Гвинее.
func (s *Service) Catalog(ctx context.Context) ([]Summary, error) {
	rows, err := s.q.CatalogServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("servers: catalog query: %w", err)
	}
	now := time.Now()
	out := make([]Summary, 0, len(rows))
	for _, row := range rows {
		// LEFT JOIN отдаёт NullHealthStatus: «health ещё не прислан» обязан
		// остаться nil-статусом, а не превратиться в строку "ok" нулевой длины.
		var status *string
		if row.HealthStatus.Valid {
			value := string(row.HealthStatus.HealthStatus)
			status = &value
		}
		lat, err := strconv.ParseFloat(row.Lat, 64)
		if err != nil {
			return nil, fmt.Errorf("servers: server %s: bad lat: %w", row.ID, err)
		}
		lon, err := strconv.ParseFloat(row.Lon, 64)
		if err != nil {
			return nil, fmt.Errorf("servers: server %s: bad lon: %w", row.ID, err)
		}
		out = append(out, Summary{
			ID: row.ID.String(), Name: row.Name, CountryCode: row.CountryCode,
			City: row.City, Host: row.AdvertisedHost,
			Port: int(row.ListenPort), MTU: int(row.Mtu),
			Latitude: lat, Longitude: lon,
			Availability: Available(status, row.HealthObservedAt, now),
			CapacityMbps: row.CapacityMbps, Provider: row.Provider,
			// Region — строка, а не *string: NULL здесь означает «оператор не
			// заполнил», и null в ответе клиент прочёл бы как «поле не просили».
			Region: derefString(row.Region),
		})
	}
	return out, nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

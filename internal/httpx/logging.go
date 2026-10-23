package httpx

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
)

// routeUnmatched — значение поля route в журнале, когда не совпал ни один шаблон.
// Путь клиента не пишется никогда: в нём бывают токены в query-строке.
const routeUnmatched = "unmatched"

// journal — изменяемый аккумулятор одной строки журнала. Поля дописываются
// изнутри (route — из Envelope, subject — из WithUserID), а строка пишется снаружи
// после next.ServeHTTP: иначе user id, который появляется только после проверки
// JWT, в журнал не попал бы никогда.
type journal struct {
	mu      sync.Mutex
	route   string
	userID  uuid.UUID
	hasUser bool
}

type journalKey struct{}

func withJournal(ctx context.Context) (context.Context, *journal) {
	j := &journal{}
	return context.WithValue(ctx, journalKey{}, j), j
}

// noteRoute запоминает имя совпавшего шаблона. Вызывается ровно один раз — из
// Logging, до диспетчера, чтобы отказ лимитера и 401 тоже получили настоящее имя.
func noteRoute(ctx context.Context, pattern string) {
	if j, ok := ctx.Value(journalKey{}).(*journal); ok {
		j.mu.Lock()
		j.route = pattern
		j.mu.Unlock()
	}
}

// noteUserID — то же для субъекта. Вызывается из WithUserID (задача 9) и обязан
// быть безопасен без журнала: тесты хендлеров строят контекст сами.
func noteUserID(ctx context.Context, id uuid.UUID) {
	if j, ok := ctx.Value(journalKey{}).(*journal); ok {
		j.mu.Lock()
		j.userID, j.hasUser = id, true
		j.mu.Unlock()
	}
}

func (j *journal) attrs() []any {
	j.mu.Lock()
	defer j.mu.Unlock()
	route := j.route
	if route == "" {
		route = routeUnmatched
	}
	attrs := []any{"route", route}
	if j.hasUser {
		attrs = append(attrs, "user_id", j.userID.String())
	}
	return attrs
}

// statusWriter запоминает код ответа и то, отправлены ли уже заголовки. Переехал
// из requestid.go: единственный читатель статуса теперь Logging.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(p)
}

// Logging пишет ровно одну строку на запрос: request id, маршрут, статус,
// длительность и user id (спецификация §5.2). Заголовки, query-строка, путь и
// тело не пишутся никогда: в них живут токены, а ТЗ §10 и §15 запрещают их в
// журнале. Поэтому несуществующий маршрут записывается как "unmatched", а не тем
// путём, который прислал клиент.
//
// routes — тот же ServeMux, что отдаёт запрос ниже: журнал должен назвать маршрут
// до диспетчера, иначе 429 и 401 записались бы как "unmatched".
func Logging(next http.Handler, routes PatternResolver, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, j := withJournal(r.Context())
		req := r.WithContext(ctx)
		_, pattern := routes.Handler(r)
		noteRoute(ctx, pattern)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		// Порядок отложенных вызовов значим: они исполняются в обратном порядке,
		// поэтому recover (ниже) успевает поставить 500 до записи строки (выше).
		defer func() {
			attrs := append([]any{
				"request_id", RequestIDFromContext(ctx),
				"method", r.Method,
				"status", sw.status,
				"dur_ms", time.Since(start).Milliseconds(),
			}, j.attrs()...)
			log.Info("request", attrs...)
		}()

		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// Стек в журнал можно: он описывает наш код, а не запрос клиента.
			log.Error("handler panic",
				"request_id", RequestIDFromContext(ctx),
				"panic", fmt.Sprint(rec),
				"stack", string(debug.Stack()))
			if !sw.wrote {
				// Если обработчик уже начал писать тело, дописывать конверт
				// нельзя: клиент получил бы JSON в середине ответа.
				WriteError(sw, req, http.StatusInternalServerError, ErrInternal,
					"внутренняя ошибка", nil)
			}
		}()

		next.ServeHTTP(sw, req)
	})
}

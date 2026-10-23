package httpx

import (
	"net/http"
	"strings"
)

// PatternResolver — то, что умеет сказать, каким шаблоном будет обслужен запрос.
// *http.ServeMux удовлетворяет ему методом Handler(r); matching делает сам mux, и
// снаружи его восстановить нечем.
type PatternResolver interface {
	Handler(*http.Request) (http.Handler, string)
}

// probeMethods — чем Envelope спрашивает «принимает ли этот путь другой метод».
// HEAD здесь не лишняя строка: ServeMux матчит HEAD на зарегистрированный GET, и
// Allow без HEAD противоречил бы тому, что сервер действительно принимает.
var probeMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost,
	http.MethodPut, http.MethodPatch, http.MethodDelete,
}

// Envelope превращает «такого маршрута нет» и «метод не тот» в документированный
// конверт (§5.2): на оба случая ServeMux пишет plain text без request_id и
// возвращает пустой pattern — при условии, что "/" не зарегистрирован.
//
// Сборщик обязан НЕ регистрировать "/": с catch-all'ом и отсутствующий путь, и
// несовпадение метода уходят в него, pattern перестаёт быть пустым, и отличить
// 404 от 405 становится нечем.
//
// Имя маршрута в журнал здесь не пишется — это делает Logging (правило 3 выше).
func Envelope(routes PatternResolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, pattern := routes.Handler(r)
		if pattern != "" {
			handler.ServeHTTP(w, r)
			return
		}
		// Ветка «метод не тот» обязана проверяться до 404: у ServeMux оба случая
		// выглядят одинаково (pattern ""), различает их только перебор методов.
		if allow := allowedMethods(routes, r); len(allow) > 0 {
			w.Header().Set("Allow", strings.Join(allow, ", "))
			WriteError(w, r, http.StatusMethodNotAllowed, ErrMethodNotAllowed,
				"метод не разрешён для этого маршрута", map[string]any{"allowed": allow})
			return
		}
		WriteError(w, r, http.StatusNotFound, ErrNotFound, "маршрут не найден", nil)
	})
}

func allowedMethods(routes PatternResolver, r *http.Request) []string {
	var allow []string
	for _, m := range probeMethods {
		// Текущий метод уже проверен: раз мы сюда дошли, pattern для него пустой.
		if m == r.Method {
			continue
		}
		// Clone, а не правка r: подменённый метод не имеет права просочиться в
		// основной запрос.
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, p := routes.Handler(probe); p != "" {
			allow = append(allow, m)
		}
	}
	return allow
}

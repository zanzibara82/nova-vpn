// probe — сервис за узлом: отвечает адресом, с которого пришёл запрос. В стенде
// единственный путь к нему из клиентской сети — туннель, поэтому адрес узла в ответе
// подтверждает прохождение пакета, а не запись пиера в конфиге.
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const listenAddr = ":8080"

func main() {
	if err := run(listenAddr); err != nil {
		log.Printf("probe остановлен: %v", err)
		os.Exit(1)
	}
}

func run(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           newMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /whoami", whoami)
	mux.HandleFunc("GET /healthz", healthz)
	return mux
}

// whoami берёт адрес только из RemoteAddr: заголовки клиент пишет сам, и доверять
// им значило бы позволить клиенту самому назвать адрес узла.
func whoami(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "не удалось определить адрес клиента", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintln(w, host)
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

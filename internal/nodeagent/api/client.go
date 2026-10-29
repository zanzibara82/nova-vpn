package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxBody ограничивает ответ: сломанный сервер не вынудит узел вычитать гигабайты.
const maxBody = 1 << 20

const defaultTimeout = 15 * time.Second

type Config struct {
	BaseURL       string
	CAFile        string
	Env           string
	AllowInsecure bool
	Timeout       time.Duration
}

type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

type StatusError struct {
	Status int
	Code   string
}

func (e *StatusError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("api: отказ %d", e.Status)
	}
	return fmt.Sprintf("api: отказ %d (%s)", e.Status, e.Code)
}

func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("api: не задан базовый адрес")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("api: базовый адрес: %w", err)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, fmt.Errorf("api: базовый адрес не должен содержать параметры")
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("api: базовый адрес не должен содержать фрагмент")
	}
	if u.User != nil {
		return nil, fmt.Errorf("api: базовый адрес не должен содержать учётные данные")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("api: базовый адрес без хоста")
	}
	if cfg.AllowInsecure && cfg.Env != "dev" {
		return nil, fmt.Errorf("api: пропуск проверки сертификата допустим только в dev")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !cfg.AllowInsecure || cfg.Env != "dev" {
			return nil, fmt.Errorf("api: схема http допустима только в dev с пропуском проверки")
		}
	default:
		return nil, fmt.Errorf("api: неподдерживаемая схема %q", u.Scheme)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.AllowInsecure {
		tlsCfg.InsecureSkipVerify = true
	}
	if cfg.CAFile != "" {
		raw, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("api: файл CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("api: в файле CA нет сертификатов")
		}
		tlsCfg.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		baseURL: strings.TrimRight(u.String(), "/"),
		hc: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) SetToken(token string) {
	c.token = token
}

func (c *Client) Enroll(ctx context.Context, bootstrap, publicKey string) (NodeToken, error) {
	var out NodeToken
	req := EnrollRequest{BootstrapToken: bootstrap, PublicKey: publicKey}
	status, _, err := c.do(ctx, http.MethodPost, "/internal/v1/nodes/enroll", req, &out, "", nil)
	if err != nil {
		return NodeToken{}, err
	}
	if status != http.StatusOK {
		return NodeToken{}, &StatusError{Status: status}
	}
	return out, nil
}

func (c *Client) Desired(ctx context.Context, serverID, etag string) (DesiredSet, string, bool, error) {
	var header http.Header
	if etag != "" {
		header = http.Header{"If-None-Match": []string{etag}}
	}
	var out DesiredSet
	status, respHeader, err := c.do(ctx, http.MethodGet, "/internal/v1/nodes/"+url.PathEscape(serverID)+"/desired", nil, &out, c.token, header)
	if err != nil {
		return DesiredSet{}, "", false, err
	}
	newETag := respHeader.Get("ETag")
	if status == http.StatusNotModified {
		return DesiredSet{}, newETag, true, nil
	}
	if status != http.StatusOK {
		return DesiredSet{}, "", false, &StatusError{Status: status}
	}
	var missing []string
	if out.ServerID == "" {
		missing = append(missing, "server_id")
	}
	if out.TunnelAddress == "" {
		missing = append(missing, "tunnel_address")
	}
	if out.MeasuredAt.IsZero() {
		missing = append(missing, "measured_at")
	}
	if len(missing) > 0 {
		return DesiredSet{}, "", false, fmt.Errorf("api: неполный набор: нет %s", strings.Join(missing, ", "))
	}
	return out, newETag, false, nil
}

func (c *Client) Observed(ctx context.Context, serverID string, rep ObservedReport) error {
	status, _, err := c.do(ctx, http.MethodPost, "/internal/v1/nodes/"+url.PathEscape(serverID)+"/observed", rep, nil, c.token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return &StatusError{Status: status}
	}
	return nil
}

func (c *Client) Heartbeat(ctx context.Context, serverID string, hb Heartbeat) error {
	status, _, err := c.do(ctx, http.MethodPost, "/internal/v1/nodes/"+url.PathEscape(serverID)+"/heartbeat", hb, nil, c.token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return &StatusError{Status: status}
	}
	return nil
}

func (c *Client) RotateToken(ctx context.Context, serverID string) (NodeToken, error) {
	var out NodeToken
	status, _, err := c.do(ctx, http.MethodPost, "/internal/v1/nodes/"+url.PathEscape(serverID)+"/token/rotate", nil, &out, c.token, nil)
	if err != nil {
		return NodeToken{}, err
	}
	if status != http.StatusOK {
		return NodeToken{}, &StatusError{Status: status}
	}
	return out, nil
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, token string, header http.Header) (int, http.Header, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, nil, fmt.Errorf("api: тело запроса: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return 0, nil, fmt.Errorf("api: запрос: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for name, values := range header {
		req.Header[name] = values
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("api: запрос: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, resp.Header, nil
	}
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, resp.Header, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, resp.Header, fmt.Errorf("api: чтение ответа: %w", err)
	}
	if len(raw) > maxBody {
		return resp.StatusCode, resp.Header, fmt.Errorf("api: ответ больше %d байт", maxBody)
	}
	if resp.StatusCode >= 300 {
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &env)
		return resp.StatusCode, resp.Header, &StatusError{Status: resp.StatusCode, Code: env.Error.Code}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, resp.Header, fmt.Errorf("api: разбор ответа: %w", err)
		}
	}
	return resp.StatusCode, resp.Header, nil
}

type EnrollRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	PublicKey      string `json:"public_key"`
}

type NodeToken struct {
	ServerID  string `json:"server_id"`
	NodeToken string `json:"node_token"`
}

type DesiredSet struct {
	ServerID      string        `json:"server_id"`
	ConfigVersion int64         `json:"config_version"`
	MTU           int           `json:"mtu"`
	ListenPort    int           `json:"listen_port"`
	TunnelAddress string        `json:"tunnel_address"`
	DNSServers    []string      `json:"dns_servers"`
	KeepaliveSec  int           `json:"keepalive_sec"`
	Peers         []DesiredPeer `json:"peers"`
	MeasuredAt    time.Time     `json:"measured_at"`
}

type DesiredPeer struct {
	PublicKey  string    `json:"public_key"`
	AllowedIPs []string  `json:"allowed_ips"`
	ExpiresAt  time.Time `json:"expires_at"`
	State      string    `json:"state"`
}

type ObservedReport struct {
	ConfigVersion    int64          `json:"config_version"`
	InterfaceRxBytes int64          `json:"interface_rx_bytes"`
	InterfaceTxBytes int64          `json:"interface_tx_bytes"`
	Peers            []ObservedPeer `json:"peers"`
}

type ObservedPeer struct {
	PublicKey       string     `json:"public_key"`
	LatestHandshake *time.Time `json:"latest_handshake"`
	RxBytes         int64      `json:"rx_bytes"`
	TxBytes         int64      `json:"tx_bytes"`
}

type Heartbeat struct {
	AgentVersion         string   `json:"agent_version"`
	AgentUptimeSec       int64    `json:"agent_uptime_sec"`
	Load1                *float64 `json:"load1"`
	CPUPct               *float64 `json:"cpu_pct"`
	AppliedConfigVersion int64    `json:"applied_config_version"`
	Stale                bool     `json:"stale"`
}

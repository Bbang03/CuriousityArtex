package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const closedLoopRangeMaxBody = 1 << 20
const closedLoopRangeMaxExport = 64 << 20
const closedLoopRangeTimeout = 90 * time.Second

var closedLoopRangeToken = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
var closedLoopRangeTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: closedLoopRangeTimeout,
	MaxConnsPerHost:       4, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
}

// Browser clients never supply a bridge URL, cloud credential or bearer token.
// Only this fixed route map is reachable after the normal ARTEX login guard.
func (s *Server) registerClosedLoopRange(mux *http.ServeMux) {
	for _, route := range []struct{ method, path, upstream string }{
		{"GET", "/status", "/status"},
		{"GET", "/cycles", "/cycles"},
		{"POST", "/cycles", "/cycles"},
		{"GET", "/cycles/{id}", "/cycles/{id}"},
		{"POST", "/cycles/{id}/collect", "/cycles/{id}/collect"},
		{"POST", "/cycles/{id}/suggest", "/cycles/{id}/suggest"},
		{"POST", "/cycles/{id}/candidate", "/cycles/{id}/candidate"},
		{"POST", "/cycles/{id}/rerun", "/cycles/{id}/rerun"},
		{"GET", "/cycles/{id}/export", "/cycles/{id}/export"},
	} {
		mux.HandleFunc(route.method+" /api/closed-loop/range"+route.path, func(w http.ResponseWriter, r *http.Request) {
			s.proxyClosedLoopRange(w, r, route.method, route.upstream, closedLoopRangeTimeout)
		})
	}
}

type closedLoopRangeConfig struct {
	base  *url.URL
	token string
}

func loadClosedLoopRangeConfig() (*closedLoopRangeConfig, bool) {
	raw := strings.TrimSpace(os.Getenv("ARTEX_RANGE_BRIDGE_URL"))
	file := strings.TrimSpace(os.Getenv("ARTEX_RANGE_BRIDGE_TOKEN_FILE"))
	if raw == "" && file == "" {
		return nil, false
	}
	if raw == "" || file == "" {
		return nil, true
	}
	base, err := url.Parse(raw)
	if err != nil || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Scheme != "http" && base.Scheme != "https") || (base.Path != "" && base.Path != "/") || base.RawPath != "" {
		return nil, true
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, true
	}
	defer f.Close()
	secret, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(secret) > 4096 {
		return nil, true
	}
	token := strings.TrimSpace(string(secret))
	if len(token) < 16 || len(token) > 4096 || !closedLoopRangeToken.MatchString(token) {
		return nil, true
	}
	base.Path = ""
	return &closedLoopRangeConfig{base: base, token: token}, true
}

func rangeCredentialKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
	switch normalized {
	case "token", "accesstoken", "refreshtoken", "bearertoken", "bridgetoken", "authorization", "password", "passwd", "secret", "secrets", "secretkey", "apikey", "accesskey", "accesskeyid", "secretaccesskey", "sessiontoken", "credentials", "credential", "credentialset", "privatekey":
		return true
	}
	return false
}

// Defense in depth for an accidentally verbose bridge response: credential
// fields and the bridge's actual token cannot reach browser JSON or an export.
func sanitizeRangeJSON(v any, token string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			if rangeCredentialKey(k) {
				continue
			}
			safeKey := strings.ReplaceAll(k, token, "[redacted]")
			out[safeKey] = sanitizeRangeJSON(value, token)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = sanitizeRangeJSON(value, token)
		}
		return out
	case string:
		return strings.ReplaceAll(x, token, "[redacted]")
	default:
		return x
	}
}
func decodeRangeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("range JSON object required")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("extra range JSON input")
	}
	return value, nil
}
func (s *Server) proxyClosedLoopRange(w http.ResponseWriter, r *http.Request, method, path string, timeout time.Duration) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.RawQuery != "" {
		writeErr(w, 400, "실습 연결 API에는 추가 조회 조건을 전달할 수 없습니다")
		return
	}
	if strings.Contains(path, "{id}") {
		id := r.PathValue("id")
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != strings.ToLower(id) {
			writeErr(w, 400, "올바른 실습 반복 UUID를 입력하세요")
			return
		}
		path = strings.Replace(path, "{id}", parsed.String(), 1)
	}
	cfg, configured := loadClosedLoopRangeConfig()
	if cfg == nil {
		if method == http.MethodGet && path == "/status" {
			message := "AWS 실습 브리지가 연결되지 않았습니다"
			if configured {
				message = "실습 브리지의 서버 연결 설정을 확인하세요"
			}
			writeJSON(w, 200, map[string]any{"configured": configured, "ready": false, "message": message})
			return
		}
		writeErr(w, 409, "실습 브리지의 서버 연결 설정을 먼저 확인하세요")
		return
	}
	var body io.Reader
	if method == http.MethodPost {
		raw, err := io.ReadAll(io.LimitReader(r.Body, closedLoopRangeMaxBody+1))
		if err != nil {
			writeErr(w, 400, "실습 요청 본문을 읽지 못했습니다")
			return
		}
		if len(raw) > closedLoopRangeMaxBody {
			writeErr(w, 413, "실습 요청은 1 MiB 이하여야 합니다")
			return
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			raw = []byte(`{}`)
		}
		if _, err = decodeRangeJSON(raw); err != nil {
			writeErr(w, 400, "실습 요청은 하나의 JSON 객체여야 합니다")
			return
		}
		body = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	endpoint := *cfg.base
	endpoint.Path = path
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		writeErr(w, 502, "실습 브리지 요청을 만들지 못했습니다")
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Transport: closedLoopRangeTransport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			writeErr(w, 504, "실습 브리지 응답이 지연됐습니다. 새 공격을 반복 시작하지 말고 반복 기록 상태를 확인하세요")
			return
		}
		writeErr(w, 502, "실습 브리지에 연결하지 못했습니다. 서버 연결 상태를 확인하세요")
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		writeErr(w, 502, "실습 브리지 인증 설정을 확인하세요")
		return
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 || response.StatusCode >= 500 {
		writeErr(w, 502, "실습 브리지가 요청을 처리하지 못했습니다. 반복 기록 상태를 확인하세요")
		return
	}
	// Original Sysmon XML and native search replies are only returned by the
	// explicit export endpoint. Keep normal browser responses at 1 MiB.
	maxResponse := closedLoopRangeMaxBody
	export := method == http.MethodGet && strings.HasSuffix(path, "/export")
	if export {
		maxResponse = closedLoopRangeMaxExport
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maxResponse)+1))
	if err != nil {
		if ctx.Err() != nil {
			writeErr(w, 504, "실습 브리지 응답이 지연됐습니다. 반복 기록 상태를 확인하세요")
		} else {
			writeErr(w, 502, "실습 브리지 응답을 끝까지 읽지 못했습니다")
		}
		return
	}
	if len(raw) > maxResponse {
		if export {
			writeErr(w, 502, "실습 원본 내보내기가 64 MiB 한도를 초과했습니다")
		} else {
			writeErr(w, 502, "실습 브리지 응답이 1 MiB 한도를 초과했습니다")
		}
		return
	}
	value, err := decodeRangeJSON(raw)
	if err != nil {
		writeErr(w, 502, "실습 브리지의 JSON 응답을 확인하지 못했습니다")
		return
	}
	// Only structured client errors (validation/conflict/not found) are relayed.
	// Raw errors, cookies, URLs, redirects and authentication headers are never copied.
	switch response.StatusCode {
	case 200, 201, 202, 400, 404, 409, 422, 429:
	default:
		writeErr(w, 502, "실습 브리지 응답 상태를 확인하지 못했습니다")
		return
	}
	if path == "/status" && response.StatusCode == 200 {
		value.(map[string]any)["configured"] = true
	}
	if export && response.StatusCode == 200 {
		id := r.PathValue("id")
		w.Header().Set("Content-Disposition", `attachment; filename="range-cycle-`+strings.ToLower(id)+`.json"`)
	}
	writeJSON(w, response.StatusCode, sanitizeRangeJSON(value, cfg.token))
}

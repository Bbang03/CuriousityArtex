package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testRangeBridgeToken = "isolated-range-bridge-token-never-browser"

func rangeProxyFixture(t *testing.T, upstream http.Handler) (*Server, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	bridge := httptest.NewServer(upstream)
	t.Cleanup(bridge.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(testRangeBridgeToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_RANGE_BRIDGE_URL", bridge.URL)
	t.Setenv("ARTEX_RANGE_BRIDGE_TOKEN_FILE", file)
	s := &Server{jwtKey: []byte("range-proxy-test-auth-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Cookie", "browser-cookie-must-not-forward=secret")
		r.Header.Set("X-Arbitrary-Proxy", "not-forwarded")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	return s, request
}
func TestClosedLoopRangeAuthenticationAndDisabled(t *testing.T) {
	t.Setenv("ARTEX_RANGE_BRIDGE_URL", "")
	t.Setenv("ARTEX_RANGE_BRIDGE_TOKEN_FILE", "")
	s := &Server{jwtKey: []byte("disabled-range-test-key")}
	handler := s.Handler()
	base := "/api/closed-loop/range"
	id := uuid.NewString()
	for _, route := range []struct{ method, path string }{{"GET", base + "/status"}, {"GET", base + "/cycles"}, {"POST", base + "/cycles"}, {"GET", base + "/cycles/" + id}, {"POST", base + "/cycles/" + id + "/collect"}, {"POST", base + "/cycles/" + id + "/suggest"}, {"POST", base + "/cycles/" + id + "/candidate"}, {"POST", base + "/cycles/" + id + "/rerun"}, {"GET", base + "/cycles/" + id + "/export"}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatal("unauthenticated range proxy", route.path, w.Code)
		}
		token, _ := signJWT(s.jwtKey)
		r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := 409
		if strings.HasSuffix(route.path, "/status") {
			want = 200
			if !strings.Contains(w.Body.String(), `"configured":false`) || !strings.Contains(w.Body.String(), `"ready":false`) {
				t.Fatal("disabled status", w.Body.String())
			}
		}
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("disabled proxy", route.path, w.Code)
		}
	}
}
func TestClosedLoopRangeFixedRoutesAndCredentialIsolation(t *testing.T) {
	var calls atomic.Int32
	id := uuid.NewString()
	_, request := rangeProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testRangeBridgeToken || r.Header.Get("Cookie") != "" || r.Header.Get("X-Arbitrary-Proxy") != "" || r.URL.RawQuery != "" {
			t.Error("browser headers forwarded or bridge authorization missing")
		}
		if r.Method == "POST" {
			raw, _ := io.ReadAll(r.Body)
			if string(raw) != `{"expected_revision":2}` && string(raw) != `{}` {
				t.Error("body changed", string(raw))
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("missing JSON type")
			}
			w.WriteHeader(202)
		}
		w.Header().Set("Set-Cookie", "bridge-cookie=private")
		json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path, "ready": true, "password": "upstream-private-password", "nested": map[string]any{"credentials": map[string]any{"username": "private"}, "note": "echo " + testRangeBridgeToken}, "token": testRangeBridgeToken})
	}))
	base := "/api/closed-loop/range"
	for _, route := range []struct{ method, path string }{{"GET", "/status"}, {"GET", "/cycles"}, {"POST", "/cycles"}, {"GET", "/cycles/" + id}, {"POST", "/cycles/" + id + "/collect"}, {"POST", "/cycles/" + id + "/suggest"}, {"POST", "/cycles/" + id + "/candidate"}, {"POST", "/cycles/" + id + "/rerun"}, {"GET", "/cycles/" + id + "/export"}} {
		w := request(route.method, base+route.path, `{"expected_revision":2}`)
		want := 200
		if route.method == "POST" {
			want = 202
		}
		if w.Code != want {
			t.Fatal("fixed route", route.path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), testRangeBridgeToken) || strings.Contains(w.Body.String(), "upstream-private-password") || strings.Contains(w.Body.String(), `"credentials"`) || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("credential/header leaked", w.Body.String())
		}
		if !strings.Contains(w.Body.String(), route.path) {
			t.Fatal("wrong fixed upstream path", route.path, w.Body.String())
		}
		if route.path == "/status" && !strings.Contains(w.Body.String(), `"configured":true`) {
			t.Fatal("configured status missing")
		}
		if strings.HasSuffix(route.path, "/export") && !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") {
			t.Fatal("export disposition missing")
		}
	}
	if calls.Load() != 9 {
		t.Fatal("route calls", calls.Load())
	}
	for _, path := range []string{base + "/cycles/not-uuid", base + "/cycles/" + strings.ReplaceAll(id, "-", ""), base + "/cycles/urn:uuid:" + id, base + "/cycles/" + id + "?url=http://other.invalid", base + "/status?search=index%3D*"} {
		w := request("GET", path, "")
		if w.Code != 400 {
			t.Fatal("invalid path/query accepted", path, w.Code)
		}
	}
	if calls.Load() != 9 {
		t.Fatal("invalid route reached bridge")
	}
}
func TestClosedLoopRangeBodiesErrorsAndNoRedirect(t *testing.T) {
	var calls atomic.Int32
	_, request := rangeProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/status":
			http.Redirect(w, r, "http://other.invalid/steal?token="+testRangeBridgeToken, 302)
		case "/cycles":
			w.WriteHeader(500)
			io.WriteString(w, testRangeBridgeToken+" password private")
		}
	}))
	for _, body := range []string{`null`, `[]`, `{} {}`, `{broken}`} {
		w := request("POST", "/api/closed-loop/range/cycles", body)
		if w.Code != 400 {
			t.Fatal("invalid body accepted", body, w.Code)
		}
	}
	w := request("POST", "/api/closed-loop/range/cycles", strings.Repeat("x", closedLoopRangeMaxBody+1))
	if w.Code != 413 || calls.Load() != 0 {
		t.Fatal("oversize request forwarded", w.Code)
	}
	for _, route := range []struct{ method, path string }{{"GET", "/api/closed-loop/range/status"}, {"POST", "/api/closed-loop/range/cycles"}} {
		w = request(route.method, route.path, `{}`)
		if w.Code != 502 || strings.Contains(w.Body.String(), testRangeBridgeToken) || w.Header().Get("Location") != "" {
			t.Fatal("raw upstream error/redirect leaked", w.Code, w.Body.String())
		}
	}
}
func TestClosedLoopRangeBoundedResponseAndInvalidConfig(t *testing.T) {
	_, request := rangeProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":"`+strings.Repeat("x", closedLoopRangeMaxBody)+`"}`)
	}))
	if w := request("GET", "/api/closed-loop/range/status", ""); w.Code != 502 {
		t.Fatal("oversize response accepted", w.Code)
	}
	for _, bad := range []string{"ftp://bridge.invalid", "http://user:private@bridge.invalid", "http://bridge.invalid?token=secret", "http://bridge.invalid/other"} {
		t.Setenv("ARTEX_RANGE_BRIDGE_URL", bad)
		w := request("GET", "/api/closed-loop/range/status", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"ready":false`) || strings.Contains(w.Body.String(), "private") {
			t.Fatal("bad host config", w.Code, w.Body.String())
		}
	}
	t.Setenv("ARTEX_RANGE_BRIDGE_URL", "http://bridge.invalid")
	t.Setenv("ARTEX_RANGE_BRIDGE_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	if w := request("POST", "/api/closed-loop/range/cycles", `{}`); w.Code != 409 {
		t.Fatal("missing credential file accepted", w.Code)
	}
}
func TestClosedLoopRangeExportHasSeparateBoundedResponse(t *testing.T) {
	id := uuid.NewString()
	var oversized atomic.Bool
	_, request := rangeProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if oversized.Load() {
			// Stream past the hard export cap without retaining another 64 MiB
			// allocation in the fake bridge.
			chunk := strings.Repeat("x", 64<<10)
			for written := 0; written <= closedLoopRangeMaxExport; written += len(chunk) {
				if _, err := io.WriteString(w, chunk); err != nil {
					return
				}
			}
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"original": strings.Repeat("x", closedLoopRangeMaxBody+1),
			"note":     "private " + testRangeBridgeToken,
			"password": "export-private-password",
		})
	}))
	path := "/api/closed-loop/range/cycles/" + id
	if w := request("GET", path, ""); w.Code != 502 || !strings.Contains(w.Body.String(), "1 MiB") {
		t.Fatal("normal response cap changed", w.Code)
	}
	w := request("GET", path+"/export", "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("bounded large export rejected", w.Code)
	}
	if len(w.Body.Bytes()) <= closedLoopRangeMaxBody || strings.Contains(w.Body.String(), testRangeBridgeToken) || strings.Contains(w.Body.String(), "export-private-password") {
		t.Fatal("large export omitted evidence or leaked credentials")
	}
	oversized.Store(true)
	w = request("GET", path+"/export", "")
	if w.Code != 502 || !strings.Contains(w.Body.String(), "64 MiB") || w.Header().Get("Content-Disposition") != "" {
		t.Fatal("oversize export accepted", w.Code)
	}
}
func TestClosedLoopRangeTimeoutPreservesUnknown(t *testing.T) {
	s, _ := rangeProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	r := httptest.NewRequest("GET", "/api/closed-loop/range/status", nil)
	w := httptest.NewRecorder()
	start := time.Now()
	s.proxyClosedLoopRange(w, r, http.MethodGet, "/status", 20*time.Millisecond)
	if w.Code != 504 || time.Since(start) > time.Second || strings.Contains(w.Body.String(), testRangeBridgeToken) {
		t.Fatal("timeout not bounded or secret leaked", w.Code, w.Body.String())
	}
	// Browser cancellation is also propagated into the outbound operation.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r = r.WithContext(ctx)
	w = httptest.NewRecorder()
	s.proxyClosedLoopRange(w, r, http.MethodGet, "/status", time.Second)
	if w.Code != 504 {
		t.Fatal("request cancellation ignored", w.Code)
	}
}

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func closedLoopAPIBody() string {
	return `{"scenario":"API offline fixture","baseline_rule":{"name":"baseline","any":[{"all":[{"field":"path","op":"contains","value":"/private/","case_sensitive":true}]}]},"candidate_rule":{"name":"candidate","any":[{"all":[{"field":"path","op":"contains","value":"/private/","case_sensitive":true}]}]},"tuning_logs":"{\"event_id\":\"api-t\",\"label\":\"attack\",\"fields\":{\"path\":\"/private/tuning\"}}","evaluation_logs":"{\"event_id\":\"api-e\",\"label\":\"benign\",\"fields\":{\"path\":\"/docs/evaluation\"}}"}`
}
func TestClosedLoopAuthenticationAndBoundedInput(t *testing.T) {
	s := &Server{jwtKey: []byte("closed-loop-auth-test-key-32-bytes")}
	for _, route := range []struct{ method, path string }{{"GET", "/api/closed-loop/iterations"}, {"POST", "/api/closed-loop/suggest"}, {"POST", "/api/closed-loop/evaluate"}, {"POST", "/api/closed-loop/iterations"}, {"GET", "/api/closed-loop/iterations/1/export"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", route.path, w.Code)
		}
	}
}
func TestClosedLoopAPIPreviewSaveHistoryAndExport(t *testing.T) {
	s, _, request := purpleAPIFixture(t)
	body := closedLoopAPIBody()
	preview := request("POST", "/api/closed-loop/evaluate", body)
	if preview.Code != 200 {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body)
	}
	saved := request("POST", "/api/closed-loop/iterations", body)
	if saved.Code != 201 {
		t.Fatalf("save: %d %s", saved.Code, saved.Body)
	}
	var record db.ClosedLoopIteration
	if err := json.Unmarshal(saved.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM closed_loop_iterations WHERE id=$1`, record.ID) })
	if record.Result.EvaluationComparison.Candidate.TN != 1 || record.Input.TuningLogs != "" {
		t.Fatalf("saved: %+v", record)
	}
	history := request("GET", "/api/closed-loop/iterations?limit=100", "")
	if history.Code != 200 || !strings.Contains(history.Body.String(), `API offline fixture`) {
		t.Fatalf("history: %d %s", history.Code, history.Body)
	}
	exported := request("GET", fmt.Sprintf("/api/closed-loop/iterations/%d/export", record.ID), "")
	if exported.Code != 200 || !strings.Contains(exported.Body.String(), `api-t`) || exported.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export: %d %s", exported.Code, exported.Body)
	}
	for _, bad := range []string{`{}`, `null`, `{} {}`, strings.Replace(body, `"scenario":`, `"verdict":"passed","scenario":`, 1), strings.Replace(body, `"op":"contains"`, `"op":"exec"`, 1)} {
		response := request("POST", "/api/closed-loop/iterations", bad)
		if response.Code != 400 {
			t.Fatalf("bad accepted: %d %s", response.Code, response.Body)
		}
	}
	if response := request("GET", "/api/closed-loop/iterations?limit=101", ""); response.Code != 400 {
		t.Fatalf("limit: %d", response.Code)
	}
	if response := request("GET", "/api/closed-loop/iterations/999999999/export", ""); response.Code != 404 {
		t.Fatalf("missing: %d", response.Code)
	}
	// Supplying evaluation data to suggestion is rejected by the wire contract.
	if response := request("POST", "/api/closed-loop/suggest", `{"evaluation_logs":"heldout"}`); response.Code != 400 {
		t.Fatalf("suggest held-out leakage accepted: %d", response.Code)
	}
}

package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
)

func TestAegisOverviewRequiresAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("aegis-test-only-key")}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/aegis/overview", nil))
	if w.Code != 401 {
		t.Fatalf("unauthenticated overview: %d", w.Code)
	}
}

func TestAegisOverviewStandaloneCaseDoesNotCreateFinding(t *testing.T) {
	s, _, request := purpleAPIFixture(t)
	before, err := s.m.pg.GetAegisOverview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	input := map[string]any{
		"title": "Standalone overview fixture", "question": "Review historical accesses",
		"scope":   investigation.Scope{Target: "overview.example", Start: now.Add(-time.Hour), End: now.Add(-time.Minute)},
		"mapping": investigation.DefaultMapping(), "source_kind": "file", "file_label": "test audit export",
		"files":              []investigation.InputFile{{Name: "overview.jsonl", Content: fmt.Sprintf(`{"id":"overview-private-event","timestamp":%q,"target":"overview.example","path":"/login","status":401}`, now.Add(-30*time.Minute).Format(time.RFC3339Nano))}},
		"coverage_confirmed": true,
	}
	raw, _ := json.Marshal(input)
	w := request("POST", "/api/defensive/cases", string(raw))
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var saved struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM defensive_cases WHERE id=$1`, saved.ID) })
	w = request("GET", "/api/aegis/overview", "")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("overview: %d %s", w.Code, w.Body)
	}
	var after db.AegisOverview
	if err = json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after.Defensive.Cases != before.Defensive.Cases+1 || after.Defensive.ObservedEvents != before.Defensive.ObservedEvents+1 || after.Offensive.Findings != before.Offensive.Findings {
		t.Fatalf("case and finding counts mixed: before=%+v after=%+v", before, after)
	}
	if after.GeneratedAt.IsZero() || strings.Contains(w.Body.String(), "overview-private-event") || strings.Contains(w.Body.String(), "Review historical") {
		t.Fatal("overview must return counts, not raw case evidence")
	}
}

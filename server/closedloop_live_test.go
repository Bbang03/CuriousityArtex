package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/google/uuid"
)

func TestClosedLoopLiveAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("isolated-live-test-key")}
	base := "/api/closed-loop/live-cycles"
	for _, route := range []struct{ method, path string }{{"GET", base}, {"POST", base}, {"GET", base + "/1"}, {"GET", base + "/1/export"}, {"POST", base + "/1/collect"}, {"POST", base + "/1/suggest"}, {"PUT", base + "/1/candidate"}, {"POST", base + "/1/rerun"}, {"POST", base + "/1/stop"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: %d", route.method, route.path, w.Code)
		}
	}
}
func TestClosedLoopLiveAPIStagesAndDTO(t *testing.T) {
	s, fid, request := purpleAPIFixture(t)
	d := s.m.pg
	var aid int64
	if err := d.QueryRow(`INSERT INTO assets(type,url) VALUES('endpoint','http://live-api.test:3000/private/export.csv') RETURNING id`).Scan(&aid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE id=$1`, aid) })
	if _, err := d.Exec(`UPDATE findings SET asset_ids=$2::jsonb WHERE id=$1`, fid, fmt.Sprintf("[%d]", aid)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveDefensePlan(t.Context(), fid, db.DefensePlanInput{Hypothesis: "actual retest independent audit", RuleFormat: "query", RuleText: "existing rule"}); err != nil {
		t.Fatal(err)
	}
	source, err := d.SaveSecuritySource(t.Context(), 0, 0, "isolated reader", securitysource.Config{BaseURL: "https://logs.invalid:8089", Index: "isolated", AuditSourcetype: "test:audit", AlertSourcetype: "test:alert", CorrelationField: "verification_id", ActionField: "action"}, true, []byte("isolated-placeholder"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
	state, err := d.GetFindingDefense(t.Context(), fid)
	if err != nil {
		t.Fatal(err)
	}
	rule := closedloop.Rule{Name: "baseline", Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "equals", Value: "/private/legacy.csv", CaseSensitive: true}}}}}
	c, _, conv, _, _, err := d.CreateClosedLoopLiveCycle(t.Context(), db.ClosedLoopLiveInput{RequestID: uuid.NewString(), FindingID: fid, Scenario: "API live loop", Defense: db.DefenseExecutionInput{SourceID: source.ID, PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &state.EvidenceVersion, ExpectedSourceFingerprint: state.SourceFingerprint}, BaselineRule: rule})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM closed_loop_live_cycles WHERE id=$1`, c.ID)
		d.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID)
	})
	path := fmt.Sprintf("/api/closed-loop/live-cycles/%d", c.ID)
	w := request("GET", path, "")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("get", w.Code, w.Body.String())
	}
	var dto db.ClosedLoopLiveCycle
	if err := json.Unmarshal(w.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Baseline == nil || dto.Baseline.Retest == nil || dto.LogPath != "/" || dto.LogTarget != "live-api.test:3000" || dto.Baseline.DiagnosisSnapshot != nil || dto.Comparison.Precision != nil {
		t.Fatal("DTO/scope/preview mismatch")
	}
	for _, route := range []struct{ method, suffix, body string }{{"POST", "/collect", `{}`}, {"POST", "/suggest", `{}`}, {"POST", "/rerun", `{"expected_revision":1}`}} {
		w = request(route.method, path+route.suffix, route.body)
		if w.Code < 400 {
			t.Fatal("unfinished execution accepted", route.suffix, w.Code)
		}
	}
	w = request("PUT", path+"/candidate", `{"expected_revision":1,"rule":{},"note":"x","free_spl":"index=*"}`)
	if w.Code != 400 {
		t.Fatal("untyped/free SPL property accepted", w.Code)
	}
	w = request("POST", path+"/stop", `{}`)
	if w.Code != 200 {
		t.Fatal("stop", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Status != "stopped" || dto.Baseline.Retest.Status != "stopped" {
		t.Fatal("stop metadata mismatch")
	}
	w = request("GET", path+"/export", "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("export", w.Code)
	}
	w = request("GET", "/api/closed-loop/live-cycles", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "API live loop") {
		t.Fatal("list", w.Code)
	}
}

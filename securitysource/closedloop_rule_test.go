package securitysource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/investigation"
)

func shadowScope(q Query) investigation.Scope {
	return investigation.Scope{Target: "juice-shop:3000", PathPrefix: "/ftp", Start: q.Start, End: q.End}
}

func shadowRules() (closedloop.Rule, closedloop.Rule) {
	return closedloop.Rule{Name: "baseline", Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "rule_id", Op: "equals", Value: "942100", CaseSensitive: true}}}}},
		closedloop.Rule{Name: "candidate", Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "contains", Value: "/ftp/", CaseSensitive: false}}}}}
}

func shadowLine(at time.Time, id, baseline, candidate string, changes map[string]any, last bool) string {
	fields := map[string]any{"_time": at.Format("2006-01-02T15:04:05.000000-0700"),
		"index": "security", "sourcetype": "app:audit", "source": "native-modsecurity", "host": "waf",
		"id": id, "artex_verification_id": testCorrelation, "target": "juice-shop:3000", "path": "/ftp/test.txt",
		"rule_id": "1001001", "action": "allowed", "event_kind": "audit", "status": 200,
		baselineShadowField: baseline, candidateShadowField: candidate, "large_number": json.Number("9007199254740993"),
		"_raw": `{"native_original":"unchanged bytes","status":200}`}
	for key, value := range changes {
		fields[key] = value
	}
	raw, _ := json.Marshal(fields)
	return fmt.Sprintf("{\"preview\":false,\"lastrow\":%t,\"result\":%s}\n", last, raw)
}

func TestClosedLoopRuleSearchBoundsAndEscapes(t *testing.T) {
	c, _ := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Fatal("builder used network") })
	q := sourceQuery()
	b, cand := shadowRules()
	cand.Any[0].All[0].Value = `x" | collect index="outside" [ .* % _ \\ end`
	search, err := BuildClosedLoopRuleSearch(c, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
	if err != nil {
		t.Fatal(err)
	}
	for _, mandatory := range []string{`search index="security" (sourcetype="app:audit")`, `match(trim(tostring('target'))`,
		` = "/ftp"`, `mvcount('artex_verification_id') = 1 AND 'artex_verification_id' = "` + testCorrelation + `"`,
		`case(isnull('rule_id') OR mvcount('rule_id') != 1`, `"_aegis_shadow_baseline"=case`, `"_aegis_shadow_candidate"=case`} {
		if !strings.Contains(search, mandatory) {
			t.Errorf("missing bound/typed evaluation: %s", mandatory)
		}
	}
	if strings.Contains(search, `sourcetype="waf:alert"`) || strings.Contains(search, " | where '_aegis_shadow_candidate'") ||
		strings.Count(search, " | head ") != 1 || !strings.HasSuffix(search, " | head 10001") {
		t.Fatal("input denominator lost or scope/limit changed")
	}
	if !strings.Contains(search, investigationLiteral(regexp.QuoteMeta(strings.ToLower(cand.Any[0].All[0].Value)))) {
		t.Fatal("contains literal was not escaped as an eval regex data argument")
	}
}

func TestClosedLoopRuleValidationBeforeNetwork(t *testing.T) {
	c, auth := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid rule reached network") })
	q, mapping := sourceQuery(), investigation.DefaultMapping()
	b, cand := shadowRules()
	for _, forbidden := range []string{"id", "event_id", "EVENT_ID", "_time", "timestamp", "label", "ground_truth", "artex_verification_id", "correlation_id",
		"request_uid", "alert_created_at", "_raw", "source", "rule_sha256", "_aegis_shadow_baseline", "arbitrary_field", `path' | delete`} {
		bad := cand
		bad.Any = []closedloop.Branch{{All: []closedloop.Condition{{Field: forbidden, Op: "equals", Value: "value"}}}}
		if _, err := FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), mapping, b, bad); err == nil {
			t.Fatalf("forbidden field accepted: %s", forbidden)
		}
	}
	for _, value := range []string{"nul\x00data", "line\ncommand", "bad\xff"} {
		bad := cand
		bad.Any = []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "contains", Value: value}}}}
		if _, err := FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), mapping, b, bad); err == nil {
			t.Fatal("invalid literal accepted")
		}
	}
	for _, modify := range []func(*Query, *investigation.Scope, *investigation.Mapping){
		func(q *Query, s *investigation.Scope, m *investigation.Mapping) { q.CorrelationID = "*" },
		func(q *Query, s *investigation.Scope, m *investigation.Mapping) { s.End = s.End.Add(time.Second) },
		func(q *Query, s *investigation.Scope, m *investigation.Mapping) {
			q.Start = q.End.Add(-25 * time.Hour)
			s.Start = q.Start
		},
		func(q *Query, s *investigation.Scope, m *investigation.Mapping) { s.Target = "" },
		func(q *Query, s *investigation.Scope, m *investigation.Mapping) { s.PathPrefix = "" },
		func(q *Query, s *investigation.Scope, m *investigation.Mapping) { m.VerificationID = "alternate_uuid" },
	} {
		badQ, badS, badM := q, shadowScope(q), mapping
		modify(&badQ, &badS, &badM)
		if _, err := FetchClosedLoopRules(t.Context(), c, auth, badQ, badS, badM, b, cand); err == nil {
			t.Fatal("mandatory scope accepted after modification")
		}
	}
	var large []closedloop.Branch
	for i := 0; i < closedloop.MaxBranches; i++ {
		var all []closedloop.Condition
		for j := 0; j < closedloop.MaxConditions; j++ {
			all = append(all, closedloop.Condition{Field: "path", Op: "equals", Value: strings.Repeat("x", 1024)})
		}
		large = append(large, closedloop.Branch{All: all})
	}
	cand.Any = large
	if _, err := BuildClosedLoopRuleSearch(c, q, shadowScope(q), mapping, b, cand); err == nil {
		t.Fatal("unbounded generated query accepted")
	}
}

func TestClosedLoopRuleNativeQueryAndImmutableEvidence(t *testing.T) {
	q := sourceQuery()
	b, cand := shadowRules()
	wantBody := shadowLine(q.Start.Add(time.Second), "native-audit-id", "no_match", "match", nil, true)
	calls := 0
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/services/search/v2/jobs/export" {
			t.Error("non-read-only operation")
		}
		if user, password, ok := r.BasicAuth(); !ok || user != "reader" || password != "test-only" {
			t.Error("wrong credential scope")
		}
		_ = r.ParseForm()
		if r.Form.Get("earliest_time") != investigationEpoch(q.Start) || r.Form.Get("latest_time") != investigationEpoch(q.End) || r.Form.Get("preview") != "false" || r.Form.Get("output_time_format") != splunkOutputTimeFormat {
			t.Error("native search time bounds changed")
		}
		if !strings.Contains(r.Form.Get("search"), baselineShadowField) || !strings.Contains(r.Form.Get("search"), candidateShadowField) {
			t.Error("one of the two native rule evaluations missing")
		}
		fmt.Fprint(w, wantBody)
	})
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:1")
	out, err := FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !out.Complete || out.Scope != "splunk_shadow_rule_evaluation" || len(out.Events) != 1 || len(out.Files) != 2 || out.Truncated != 0 {
		t.Fatalf("native evidence incorrect: %+v", out)
	}
	if out.Events[0].EventID != "native-audit-id" || out.Events[0].Baseline != "no_match" || out.Events[0].Candidate != "match" || !strings.Contains(string(out.Events[0].Raw), "9007199254740993") || !strings.Contains(string(out.Events[0].Raw), "native_original") {
		t.Fatal("native source identity/bytes/numeric precision lost")
	}
	if out.Files[0].Content != wantBody || out.Files[0].SHA256 != closedloop.Hash([]byte(wantBody)) || out.Files[0].Bytes != len(wantBody) || out.Files[0].Rows != 1 {
		t.Fatal("exact upstream export provenance lost")
	}
	if out.QueryStartedAt.IsZero() || out.QueryFinishedAt.Before(out.QueryStartedAt) || !out.CollectedAt.Equal(out.QueryFinishedAt) || out.BaselineRuleSHA256 == "" || out.CandidateRuleSHA256 == "" {
		t.Fatal("rule or query timing provenance missing")
	}
}

func TestClosedLoopRuleUnknownAndBooleanSemantics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   closedloop.Rule
		fields map[string]any
		want   string
	}{
		{"missing", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "equals", Value: "x"}}}}}, map[string]any{}, "unknown"},
		{"multi", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "equals", Value: "x"}}}}}, map[string]any{"path": []any{"x", "y"}}, "unknown"},
		{"nested array", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "equals", Value: "x"}}}}}, map[string]any{"path": []any{[]any{"x"}}}, "unknown"},
		{"duplicate extraction", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "equals", Value: "X"}}}}}, map[string]any{"path": []any{"x", "x"}}, "match"},
		{"false AND unknown", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "method", Op: "equals", Value: "POST"}, {Field: "missing", Op: "equals", Value: "x"}}}}}, map[string]any{"method": "GET"}, "no_match"},
		{"true OR unknown", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "method", Op: "equals", Value: "GET"}}}, {All: []closedloop.Condition{{Field: "missing", Op: "equals", Value: "x"}}}}}, map[string]any{"method": "GET"}, "match"},
		{"null", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "equals", Value: "x"}}}}}, map[string]any{"path": nil}, "unknown"},
		{"boolean scalar", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "matched_rules", Op: "equals", Value: "true", CaseSensitive: true}}}}}, map[string]any{"matched_rules": true}, "match"},
		{"truncated request", closedloop.Rule{Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "query_string", Op: "contains", Value: "needle"}}}}}, map[string]any{"query_string": "retained prefix", "query_string_truncated": true}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchClosedLoopRule(tc.fields, nil, tc.rule); got != tc.want {
				t.Fatalf("state=%s want=%s", got, tc.want)
			}
		})
	}
}

func TestClosedLoopRuleRejectsScopeAndStateConflicts(t *testing.T) {
	q := sourceQuery()
	b, cand := shadowRules()
	for name, changes := range map[string]map[string]any{
		"wrong target": {"target": "other:3000"}, "wrong path": {"path": "/ftp-evil/x"},
		"wrong correlation": {"artex_verification_id": "other-execution-uuid"}, "wrong time": {"_time": q.End.Format(time.RFC3339Nano)},
		"wrong index": {"index": "outside"}, "wrong sourcetype": {"sourcetype": "waf:alert"},
		"unknown multi": {"rule_id": []any{"1001001", "942100"}}, "forged state": {candidateShadowField: "no_match"},
	} {
		t.Run(name, func(t *testing.T) {
			c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, shadowLine(q.Start.Add(time.Second), "id", "no_match", "match", changes, true))
			})
			out, err := FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
			if err != nil {
				t.Fatal(err)
			}
			if out.Complete || len(out.Warnings) < 3 {
				t.Fatal("conflicting source or native result stayed conclusive")
			}
			if len(out.Events) > 0 && out.Events[0].Candidate != "unknown" {
				t.Fatal("untrusted native state counted as a match")
			}
		})
	}
}

func TestClosedLoopRuleCompletedEmptyAndPartialStreams(t *testing.T) {
	q := sourceQuery()
	b, cand := shadowRules()
	for _, tc := range []struct {
		name, body string
		complete   bool
	}{
		{"terminal empty", `{"preview":false,"lastrow":true}` + "\n", true},
		{"empty body", "", false},
		{"diagnostic only", `{"messages":[{"type":"INFO"}]}` + "\n", false},
		{"missing marker", shadowLine(q.Start.Add(time.Second), "id", "no_match", "match", nil, false), false},
		{"preview", `{"preview":true,"lastrow":true,"result":{}}` + "\n", false},
		{"warning", `{"messages":[{"type":"WARN","text":"private details"}]}` + "\n" + shadowLine(q.Start.Add(time.Second), "id", "no_match", "match", nil, true), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
			out, err := FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
			if err != nil || out.Complete != tc.complete || len(out.Files) != 2 || strings.Contains(strings.Join(out.Warnings, " "), "private details") {
				t.Fatalf("wrong completion/provenance: complete=%v err=%v", out.Complete, err)
			}
		})
	}
}

func TestClosedLoopRuleFailedQueryStillHasSafeProvenance(t *testing.T) {
	q := sourceQuery()
	b, cand := shadowRules()
	for _, tc := range []struct {
		name, body, code string
		status           int
		wantFile         bool
	}{
		{"fatal", `{"messages":[{"type":"ERROR","text":"private details"}]}`, "invalid_export", 200, true},
		{"malformed", `{"result":{}`, "invalid_export", 200, true},
		{"duplicate native", `{"lastrow":true,"result":{"id":"a","id":"b"}}`, "invalid_events", 200, true},
		{"too large", strings.Repeat(" ", maxResponseBytes+1), "response_limit", 200, true},
		{"denied", "private auth details", "http_error", 403, false},
		{"redirect", "private auth details", "http_error", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) })
			out, err := FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
			// Duplicate native fields are rejected by the domain parser as an
			// incomplete row; the completed export itself remains preserved.
			if tc.name == "duplicate native" {
				if (err != nil && out.ErrorCode != "invalid_events") || out.Complete || len(out.Events) != 0 || len(out.Files) != 2 {
					t.Fatal("duplicate native values accepted")
				}
				return
			}
			if err == nil || out == nil || out.Complete || out.ErrorCode != tc.code || out.QueryFinishedAt.IsZero() || out.Query == "" {
				t.Fatalf("failure attempt missing: out=%+v err=%v", out, err)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(strings.Join(out.Warnings, " "), "private") || (!tc.wantFile && len(out.Files) > 0) {
				t.Fatal("authentication diagnostics disclosed")
			}
			if tc.wantFile && (len(out.Files) != 1 || out.Files[0].SHA256 == "" || out.Files[0].Bytes > maxResponseBytes) {
				t.Fatal("bounded original failure evidence missing")
			}
		})
	}
	c, auth := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("cancelled search reached server") })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, err := FetchClosedLoopRules(ctx, c, auth, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
	if err == nil || out.ErrorCode != "request_cancelled" || out.Complete {
		t.Fatal("cancelled attempt became conclusive")
	}
}

func TestClosedLoopRuleFilePreservesUploadAndExcludesAlerts(t *testing.T) {
	q := sourceQuery()
	b, cand := shadowRules()
	c := Config{CorrelationField: "artex_verification_id"}
	raw := fmt.Sprintf(`{"id":"native","timestamp":%q,"artex_verification_id":%q,"target":"juice-shop:3000","path":"/ftp/test.txt","rule_id":"1001001"}`, q.Start.Add(time.Second).Format(time.RFC3339Nano), q.CorrelationID)
	upload := &UploadProvenance{CoverageComplete: true, Files: []UploadedFileEvidence{{Name: "audit.jsonl", Kind: "audit", Content: raw, SHA256: closedloop.Hash([]byte(raw)), Bytes: len(raw)}}}
	evidence := &Evidence{Complete: true, WindowStart: q.Start, WindowEnd: q.End, CollectedAt: time.Now().UTC(), Upload: upload,
		Events: []Event{{ID: "native", Kind: "audit", CorrelationID: q.CorrelationID, OccurredAt: q.Start.Add(time.Second), Raw: json.RawMessage(raw)},
			{ID: "real-alert", Kind: "alert", CorrelationID: q.CorrelationID, OccurredAt: q.Start.Add(time.Second), Raw: json.RawMessage(raw)}}}
	before, _ := json.Marshal(evidence)
	out, err := EvaluateClosedLoopFile(c, q, shadowScope(q), investigation.DefaultMapping(), b, cand, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Complete || out.Scope != "file_rule_evaluation" || out.Query != "" || len(out.Events) != 1 || out.Events[0].Baseline != "no_match" || out.Events[0].Candidate != "match" || !reflect.DeepEqual(upload, out.Upload) {
		t.Fatal("file evaluation changed provenance or fabricated native alert")
	}
	after, _ := json.Marshal(evidence)
	if string(before) != string(after) {
		t.Fatal("original evidence mutated")
	}
	out.Upload.Files[0].Content = "redacted output"
	if evidence.Upload.Files[0].Content != raw {
		t.Fatal("redacting result changed original immutable upload")
	}
	evidence.Events[0].CorrelationID = "other-execution-uuid"
	out, err = EvaluateClosedLoopFile(c, q, shadowScope(q), investigation.DefaultMapping(), b, cand, evidence)
	if err != nil || out.Complete || len(out.Events) != 0 {
		t.Fatal("file source scope was not independently checked")
	}
}

func TestClosedLoopRuleEventStorageAndReadFailureAreIncomplete(t *testing.T) {
	q := sourceQuery()
	b, cand := shadowRules()
	var body strings.Builder
	for i := 0; i <= investigation.MaxEvents; i++ {
		body.WriteString(shadowLine(q.Start.Add(time.Second), fmt.Sprintf("audit-%d", i), "no_match", "match", nil, i == investigation.MaxEvents))
	}
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body.String()) })
	out, err := FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
	if err != nil || out.Complete || out.Truncated != 1 || len(out.Events) != investigation.MaxEvents || out.TotalRows != investigation.MaxEvents+1 || len(out.Files) != 2 {
		t.Fatalf("event cap failed to affect completeness: events=%d truncated=%d complete=%v error=%v", len(out.Events), out.Truncated, out.Complete, err)
	}
	partialBody := shadowLine(q.Start.Add(time.Second), "partial-audit", "no_match", "match", nil, true)
	c, auth = sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(partialBody)+100))
		fmt.Fprint(w, partialBody)
	})
	out, err = FetchClosedLoopRules(t.Context(), c, auth, q, shadowScope(q), investigation.DefaultMapping(), b, cand)
	if err == nil || out.Complete || out.ErrorCode != "response_interrupted" || len(out.Files) != 1 || out.Files[0].Content != partialBody || out.Files[0].SHA256 != closedloop.Hash([]byte(partialBody)) {
		t.Fatal("transport interruption became complete or lost original prefix evidence")
	}
}

func TestPurpleSourceMissingFinalMarkerCannotBecomeMiss(t *testing.T) {
	q := sourceQuery()
	full := resultLine(q.Start.Add(time.Second), q.CorrelationID, "allowed")
	for _, tc := range []struct {
		name, stream string
		complete     bool
	}{
		{"completed row", full, true},
		{"completed terminal", strings.Replace(full, `"lastrow":true`, `"lastrow":false`, 1) + `{"lastrow":true}` + "\n", true},
		{"partial rows", strings.Replace(full, `"lastrow":true`, `"lastrow":false`, 1), false},
		{"empty body", "", false},
		{"completed empty", `{"lastrow":true}` + "\n", true},
		{"partial then error", strings.Replace(full, `"lastrow":true`, `"lastrow":false`, 1) + `{"messages":[{"type":"ERROR"}]}` + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := &Evidence{Complete: true, Events: []Event{}, Warnings: []string{}}
			err := parseExport([]byte(tc.stream), "alert", Config{Index: "security", CorrelationField: "artex_verification_id", ActionField: "action"}, q, out)
			if err != nil {
				out.Complete = false
			}
			if out.Complete != tc.complete {
				t.Fatal("unfinished native alert export became complete")
			}
		})
	}
}

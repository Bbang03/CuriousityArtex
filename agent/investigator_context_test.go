package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/investigation"
)

func TestInvestigatorInventoryUsesActualKindsAndRareVerificationSamples(t *testing.T) {
	r := certTestRun(t)
	r.events = map[string]investigation.Event{}
	r.opts.Title = "/ftp 노출 조사"
	r.opts.Collection.Mapping = investigation.DefaultMapping()
	for i := 0; i < 891; i++ {
		e := r.opts.Collection.Events[0]
		e.Ref, e.ID = fmt.Sprintf("ref-%d", i), fmt.Sprintf("id-%d", i)
		e.Raw = "private-full-log-" + strings.Repeat("x", 5000)
		e.EventKind, e.Action = "audit", "allowed"
		e.KnownARTEX = i >= 887
		if i%2 == 1 && e.KnownARTEX {
			e.EventKind = "alert"
		}
		if i >= 889 {
			e.Action = "blocked"
		}
		r.events[e.Ref] = e
	}
	input := r.plannerInput()
	var payload struct {
		Title     string `json:"case_title"`
		Inventory struct {
			Total   int                   `json:"total_events"`
			Known   int                   `json:"known_artex_events"`
			Other   int                   `json:"other_events"`
			Mapping investigation.Mapping `json:"source_field_mapping"`
			Samples []investigation.Event `json:"samples"`
			Kinds   []investigatorCount   `json:"event_kinds"`
		} `json:"evidence_inventory"`
	}
	if err := json.Unmarshal([]byte(input), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Title != r.opts.Title || payload.Inventory.Total != 891 || payload.Inventory.Known != 4 || payload.Inventory.Other != 887 || payload.Inventory.Mapping.Target != "target" {
		t.Fatalf("inventory=%+v", payload)
	}
	if len(payload.Inventory.Samples) > 8 || len(payload.Inventory.Kinds) != 2 || strings.Contains(input, "private-full-log") {
		t.Fatal("inventory omitted kinds, exceeded cap, or leaked full raw")
	}
	knownBlocked, knownAllowed, alert := false, false, false
	for _, e := range payload.Inventory.Samples {
		knownBlocked = knownBlocked || e.KnownARTEX && e.Action == "blocked"
		knownAllowed = knownAllowed || e.KnownARTEX && e.Action == "allowed"
		alert = alert || e.EventKind == "alert"
		if !r.seen[e.Ref] || r.rawSeen[e.Ref] {
			t.Fatal("normalized samples confused with raw reads")
		}
	}
	if !knownBlocked || !knownAllowed || !alert {
		t.Fatal("rare verification/alert evidence disappeared behind common audit traffic")
	}
}

func TestInvestigatorWorkerPreviewsAreBoundedAuditableAndCitable(t *testing.T) {
	r := certTestRun(t)
	r.opts.Question = "허용과 차단의 차이를 확인"
	for ref, e := range r.events {
		e.Raw = strings.Repeat("한", 2000)
		e.SourceAmbiguous = true
		r.events[ref] = e
	}
	body := r.workerInput(t.Context(), InvestigatorIntent{ID: "intent-1"})
	var payload struct {
		Question string `json:"question"`
		Previews []struct {
			Ref       string `json:"ref"`
			Raw       string `json:"raw_excerpt"`
			Truncated bool   `json:"raw_truncated"`
			Ambiguous bool   `json:"source_ambiguous"`
		} `json:"raw_previews"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Question != r.opts.Question || len(payload.Previews) != 2 {
		t.Fatalf("payload=%+v", payload)
	}
	for _, p := range payload.Previews {
		if !p.Truncated || !p.Ambiguous || len(p.Raw) > 1250 || !r.rawSeen[p.Ref] {
			t.Fatal("raw clipping/provenance/seen boundary missing")
		}
	}
	if len(r.report.Trace) != 1 || r.report.Trace[0].Kind != "evidence_preview" || len(r.report.Trace[0].EvidenceRefs) != 2 {
		t.Fatal("provided raw preview was not recorded")
	}
	out := certCall(t, r.observationTool(), `{"kind":"observed","summary":"제공된 원문 발췌를 확인함","evidence_refs":["ref-one"]}`)
	if out.IsError || len(r.report.Observations) != 1 {
		t.Fatalf("provided raw cannot be cited: %s", out.Flatten())
	}
}

func TestInvestigatorUnknownLocalKindAndEmptyPagesDoNotConsumeQueries(t *testing.T) {
	r := certTestRun(t)
	for ref, e := range r.events {
		e.EventKind = "audit"
		r.events[ref] = e
	}
	if out := certCall(t, r.searchTool(), `{"event_kind":"nginx_access"}`); !out.IsError || !strings.Contains(out.Flatten(), "audit") {
		t.Fatal("unknown kind was silently treated as absent activity")
	}
	if r.provider.snapshot().Queries != 0 {
		t.Fatal("invalid kind charged a query")
	}
	if out := certCall(t, r.searchTool(), `{"path_contains":"missing"}`); out.IsError {
		t.Fatal(out.Flatten())
	}
	if out := certCall(t, r.searchTool(), `{"path_contains":"missing","offset":20}`); !out.IsError {
		t.Fatal("empty next page accepted")
	}
	if r.provider.snapshot().Queries != 1 {
		t.Fatal("empty paging charged a query")
	}
	if out := certCall(t, r.searchTool(), `{"path_contains":"a.txt"}`); out.IsError || !strings.Contains(out.Flatten(), "ref-one") {
		t.Fatal("filtered zero prevented investigation of existing evidence")
	}
}

func TestInvestigatorEmptyRemoteScopeStopsButIncompleteAndFilteredDoNot(t *testing.T) {
	for _, tc := range []struct {
		complete bool
		filter   string
		stop     bool
	}{{true, "", true}, {false, "", false}, {true, ",\"path_contains\":\"missing\"", false}} {
		r := certTestRun(t)
		r.events = map[string]investigation.Event{}
		calls := 0
		r.opts.Search = func(ctx context.Context, q InvestigationSearch) (investigation.Collection, error) {
			calls++
			return investigation.Collection{Scope: q.Scope, Complete: tc.complete}, nil
		}
		if out := certCall(t, r.searchTool(), `{"remote":true`+tc.filter+`}`); out.IsError {
			t.Fatal(out.Flatten())
		}
		if r.emptyCompleteScope != tc.stop {
			t.Fatalf("complete=%v filter=%s stop=%v", tc.complete, tc.filter, r.emptyCompleteScope)
		}
		if tc.stop {
			if out := certCall(t, r.searchTool(), `{"remote":true,"event_kind":"audit"}`); !out.IsError || calls != 1 {
				t.Fatal("complete empty range repeatedly fetched")
			}
		}
	}
}

func TestInvestigatorRemoteWarningsDeduplicateWithoutDiscardingCollections(t *testing.T) {
	r := certTestRun(t)
	r.report.Gaps = []string{"same warning"}
	r.opts.Search = func(ctx context.Context, q InvestigationSearch) (investigation.Collection, error) {
		return investigation.Collection{Scope: q.Scope, Complete: false, Warnings: []string{"same warning", "same warning"}}, nil
	}
	for _, path := range []string{"a", "b", "c"} {
		if out := certCall(t, r.searchTool(), fmt.Sprintf(`{"remote":true,"path_contains":%q}`, path)); out.IsError {
			t.Fatal(out.Flatten())
		}
	}
	if len(r.report.Gaps) != 2 || len(r.report.Collections) != 3 {
		t.Fatalf("warnings=%v collections=%d", r.report.Gaps, len(r.report.Collections))
	}
}

func TestInvestigatorSavesObservationBeforeNextPaidCallAndPreservesOnBudget(t *testing.T) {
	o := certFixture()
	o.Budget.MaxModelCalls = 2
	p := &certScriptProvider{t: t, script: []certScriptCall{
		{"plan_investigation", `{"action":"investigate","reason":"저장된 실제 접근 근거 확인","hypothesis":"파일 요청이 관측됐을 수 있음","objective":"제공된 원본 확인"}`, nil},
		{"record_observation", `{"kind":"observed","summary":"파일 요청 기록이 있음; 전달 성공은 미확인","evidence_refs":["ref-one"]}`, nil},
	}}
	o.Provider = p
	observedAtCall := 0
	o.Emit = func(update InvestigatorProgress) {
		if update.Observation != nil {
			observedAtCall = p.calls
		}
	}
	report, err := RunInvestigation(t.Context(), o)
	if err == nil || report.Status != "budget_exhausted" || observedAtCall != 2 || len(report.Observations) != 1 || !strings.Contains(report.Summary, "관측 1건") {
		t.Fatalf("report=%+v err=%v at=%d", report, err, observedAtCall)
	}
}

func TestInvestigatorEmptyFileDoesNotStartPaidModel(t *testing.T) {
	o := certFixture()
	o.Collection.Events = nil
	p := &certScriptProvider{t: t}
	o.Provider = p
	report, err := RunInvestigation(t.Context(), o)
	if err != nil || report.Status != "insufficient_data" || p.calls != 0 || len(report.Observations) != 0 {
		t.Fatalf("report=%+v calls=%d err=%v", report, p.calls, err)
	}
}

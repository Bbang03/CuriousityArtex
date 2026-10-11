package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/google/uuid"
)

func liveTestRule(path string) closedloop.Rule {
	return closedloop.Rule{Name: "isolated rule", Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "equals", Value: path, CaseSensitive: true}}}}}
}
func liveDBFixture(t *testing.T) (*DB, int64, ClosedLoopLiveInput) {
	t.Helper()
	d, fid := purpleDB(t)
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type,url) VALUES('endpoint','http://local-loop.test:3000/private/export.csv') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })
	if _, err := d.Exec(`UPDATE findings SET asset_ids=$2::jsonb WHERE id=$1`, fid, fmt.Sprintf("[%d]", assetID)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveDefensePlan(t.Context(), fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	source := defenseExecutionSource(t, d)
	return d, fid, ClosedLoopLiveInput{RequestID: uuid.NewString(), FindingID: fid, Scenario: "isolated live loop", Defense: defenseExecutionInput(t, d, fid, source.ID), BaselineRule: liveTestRule("/private/legacy.csv")}
}
func liveCreateFixture(t *testing.T, d *DB, in ClosedLoopLiveInput) *ClosedLoopLiveCycle {
	t.Helper()
	c, _, conv, _, created, err := d.CreateClosedLoopLiveCycle(t.Context(), in)
	if err != nil || !created {
		t.Fatalf("create: %v created=%v", err, created)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM closed_loop_live_cycles WHERE id=$1`, c.ID)
		d.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID)
	})
	return c
}
func liveObserveFixture(t *testing.T, d *DB, c *ClosedLoopLiveCycle, e *DefenseExecution, alert bool, baseline, candidate closedloop.Rule) *ClosedLoopLiveCycle {
	t.Helper()
	ev := defenseExecutionEvidence(e, alert, "unknown")
	raw, _ := json.Marshal(map[string]any{"id": "audit-1", "path": "/private/export.csv", "target": "local-loop.test:3000", "method": "GET", "verification_id": e.CorrelationID, "secret_test_value": "RAW-PRIVATE-LOOP-EVIDENCE"})
	ev.Events[0].Raw = raw
	if alert {
		ev.Events[1].Raw = json.RawMessage(`{"detection_rule_id":"native.test","rule_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	}
	native, err := d.SaveDefenseAssessment(t.Context(), e.FindingID, e.ID, ev)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(baseline)
	r, _ := json.Marshal(candidate)
	shadow := &securitysource.ClosedLoopSearchResult{Scope: "splunk_shadow_rule_evaluation", Engine: securitysource.ClosedLoopRuleEngine, CorrelationID: e.CorrelationID, Complete: true, WindowStart: ev.WindowStart, WindowEnd: ev.WindowEnd, CollectedAt: time.Now().UTC(), BaselineRuleSHA256: closedloop.Hash(b), CandidateRuleSHA256: closedloop.Hash(r), Files: []investigation.FileEvidence{{Name: "native.jsonl", Content: string(raw), SHA256: closedloop.Hash(raw)}}, Events: []securitysource.ClosedLoopRuleEvent{{EventID: "audit-1", OccurredAt: ev.Events[0].OccurredAt, Baseline: "no_match", Candidate: "match", Raw: raw}}}
	if c.Current == nil {
		shadow.Events[0].Candidate = "no_match"
	}
	out, err := d.SaveClosedLoopLiveObservation(t.Context(), c.ID, e.ID, c.Revision, native, shadow)
	if err != nil {
		t.Fatal(err)
	}
	// Repeat identical source bytes creates no duplicate observation.
	again, err := d.SaveClosedLoopLiveObservation(t.Context(), c.ID, e.ID, c.Revision, native, shadow)
	if err != nil || len(out.Observations) != len(again.Observations) {
		t.Fatal("observation duplicate", err)
	}
	return out
}
func TestClosedLoopLiveActualPairAndPrivateExport(t *testing.T) {
	d, _, in := liveDBFixture(t)
	c := liveCreateFixture(t, d, in)
	same, _, _, _, created, err := d.CreateClosedLoopLiveCycle(t.Context(), in)
	if err != nil || created || same.ID != c.ID {
		t.Fatal("create idempotency", err)
	}
	changed := in
	changed.Notes = "different"
	if _, _, _, _, _, err = d.CreateClosedLoopLiveCycle(t.Context(), changed); !errors.Is(err, ErrClosedLoopLiveConflict) {
		t.Fatal("key reuse accepted", err)
	}
	if _, _, _, _, _, err = d.RerunClosedLoopLiveCycle(t.Context(), c.ID, 1); !errors.Is(err, ErrClosedLoopLiveConflict) {
		t.Fatal("unfinished rerun accepted", err)
	}
	b := completeDefenseExecutionFixture(t, d, c.Baseline)
	c = liveObserveFixture(t, d, c, b, false, in.BaselineRule, in.BaselineRule)
	if c.Status != "baseline_ready" {
		t.Fatal("baseline state", c.Status)
	}
	suggestion, err := d.SuggestClosedLoopLiveCandidate(t.Context(), c.ID)
	if err != nil || len(suggestion.AuditEventIDs) == 0 {
		t.Fatal("actual-audit proposal", err)
	}
	candidate := liveTestRule("/private/export.csv")
	c, err = d.SetClosedLoopLiveCandidate(t.Context(), c.ID, 1, candidate, "rule change, independent real run needed")
	if err != nil || c.Revision != 2 {
		t.Fatal("candidate", err)
	}
	if _, err = d.SetClosedLoopLiveCandidate(t.Context(), c.ID, 1, candidate, "stale"); !errors.Is(err, ErrClosedLoopLiveConflict) {
		t.Fatal("stale revision accepted", err)
	}
	c, _, conv, e, created, err := d.RerunClosedLoopLiveCycle(t.Context(), c.ID, 2)
	if err != nil || !created {
		t.Fatal("rerun", err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID) })
	if e.ID == b.ID || e.CorrelationID == b.CorrelationID || !e.CreatedAt.After(*b.Retest.FinishedAt) {
		t.Fatal("rerun reused actual execution")
	}
	duplicate, _, _, _, created, err := d.RerunClosedLoopLiveCycle(t.Context(), c.ID, 2)
	if err != nil || created || duplicate.Current.ID != e.ID {
		t.Fatal("rerun duplicate dispatch", err)
	}
	if _, err = d.SetClosedLoopLiveCandidate(t.Context(), c.ID, 2, candidate, "post-dispatch edit"); !errors.Is(err, ErrClosedLoopLiveConflict) {
		t.Fatal("in-flight rule changed", err)
	}
	e = completeDefenseExecutionFixture(t, d, e)
	c = liveObserveFixture(t, d, c, e, true, in.BaselineRule, candidate)
	if c.Status != "completed" || !c.Comparison.Comparable || c.Comparison.BaselineNativeDetection != "missed" || c.Comparison.CurrentNativeDetection != "detected" || c.Comparison.BaselineShadowDetection != "not_matched" || c.Comparison.CandidateShadowDetection != "matched" {
		t.Fatalf("actual comparison %+v status=%s", c.Comparison, c.Status)
	}
	if c.Comparison.Precision != nil || c.Comparison.FalsePositiveRate != nil || c.Comparison.MTTDSeconds != nil {
		t.Fatal("invented metrics")
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "RAW-PRIVATE-LOOP-EVIDENCE") || c.Observations[0].Native.Evidence != nil {
		t.Fatal("raw leaked normal detail")
	}
	exported, err := d.GetClosedLoopLiveCycle(t.Context(), c.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(exported)
	if !strings.Contains(string(raw), "RAW-PRIVATE-LOOP-EVIDENCE") {
		t.Fatal("export lost exact source evidence")
	}
	if len(c.Observations[0].NativeRuleRefs) != 1 || c.Observations[0].NativeRuleRefs[0].DetectionRuleID != "native.test" {
		t.Fatal("native rule attribution refs absent")
	}
	if c.Comparison.CandidateNativeRuleDetection != "not_attributed" {
		t.Fatal("unrelated native rule attributed to candidate")
	}
	_, safeRetest, _, _, created, err := d.CreateClosedLoopLiveCycle(t.Context(), in)
	if err != nil || created || safeRetest.Evidence != "" {
		t.Fatal("late idempotent create leaked retest evidence", err)
	}
}
func TestClosedLoopLiveAtomicScopeAndConcurrentRerun(t *testing.T) {
	d, fid, in := liveDBFixture(t)
	bad := in
	bad.LogTarget = "outside.test"
	if _, _, _, _, _, err := d.CreateClosedLoopLiveCycle(t.Context(), bad); err == nil {
		t.Fatal("outside source scope accepted")
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, fid).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed create orphaned actual run", count, err)
	}
	bad = in
	bad.BaselineRule.Any[0].All[0].Field = "verification_id"
	if _, _, _, _, _, err := d.CreateClosedLoopLiveCycle(t.Context(), bad); err == nil {
		t.Fatal("execution-ID rule accepted")
	}
	in.BaselineRule = liveTestRule("/private/legacy.csv")
	c := liveCreateFixture(t, d, in)
	e := completeDefenseExecutionFixture(t, d, c.Baseline)
	c = liveObserveFixture(t, d, c, e, false, in.BaselineRule, in.BaselineRule)
	var err error
	c, err = d.SetClosedLoopLiveCandidate(t.Context(), c.ID, 1, liveTestRule("/private/export.csv"), "candidate")
	if err != nil {
		t.Fatal(err)
	}
	var created atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _, yes, err := d.RerunClosedLoopLiveCycle(t.Context(), c.ID, c.Revision)
			if yes {
				created.Add(1)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if created.Load() != 1 {
		t.Fatal("multiple actual dispatches", created.Load())
	}
	c, err = d.GetClosedLoopLiveCycle(t.Context(), c.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Current.Retest.ConversationID != nil {
		cid := *c.Current.Retest.ConversationID
		t.Cleanup(func() { d.Exec(`DELETE FROM conversations WHERE id=$1`, cid) })
	}
	c, conv, err := d.StopClosedLoopLiveCycle(t.Context(), c.ID)
	if err != nil || c.Status != "stopped" || c.Current.Retest.Status != "stopped" || conv == nil {
		t.Fatal("stop did not seal running retest", err)
	}
	if _, _, _, _, _, err = d.RerunClosedLoopLiveCycle(t.Context(), c.ID, c.Revision); !errors.Is(err, ErrClosedLoopLiveConflict) {
		t.Fatal("stopped cycle dispatched", err)
	}
}
func TestClosedLoopLiveUnknownStaysUnknown(t *testing.T) {
	for _, state := range []string{"unknown", "unexpected"} {
		s := &securitysource.ClosedLoopSearchResult{Complete: true, Events: []securitysource.ClosedLoopRuleEvent{{Baseline: state, Candidate: "match"}}}
		if shadowState(s, false) != "inconclusive" {
			t.Fatal("unknown became negative")
		}
	}
	if shadowState(&securitysource.ClosedLoopSearchResult{Complete: true}, false) != "inconclusive" {
		t.Fatal("zero logs became no_match")
	}
	m := investigation.DefaultMapping()
	for _, field := range []string{"label", "LABEL", "artex_verification_id", "id", "_raw", "timestamp"} {
		r := liveTestRule("x")
		r.Any[0].All[0].Field = field
		if liveRuleValid(r, m) == nil {
			t.Fatal("reserved field accepted", field)
		}
	}
}

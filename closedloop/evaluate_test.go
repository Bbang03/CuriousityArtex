package closedloop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixtureInput() Input {
	return Input{Scenario: "Independent labeled local logs", BaselineRule: Rule{Name: "baseline", Any: []Branch{{All: []Condition{{Field: "path", Op: "equals", Value: "/private/legacy.csv", CaseSensitive: true}}}}}, CandidateRule: Rule{Name: "candidate", Any: []Branch{{All: []Condition{{Field: "path", Op: "contains", Value: "/private/", CaseSensitive: true}, {Field: "auth_state", Op: "equals", Value: "anonymous", CaseSensitive: true}}}}}, TuningLogs: `{"event_id":"t1","label":"attack","fields":{"path":"/private/legacy.csv","auth_state":"anonymous","method":"GET"}}
{"event_id":"t2","label":"attack","fields":{"path":"/private/export.csv","auth_state":"anonymous","method":"GET"}}
{"event_id":"t3","label":"benign","fields":{"path":"/private/legacy.csv","auth_state":"authenticated","method":"GET"}}
{"event_id":"t4","label":"benign","fields":{"path":"/docs/help","auth_state":"anonymous","method":"GET"}}`, EvaluationLogs: `{"event_id":"e1","label":"attack","fields":{"path":"/private/legacy.csv","auth_state":"anonymous","method":"HEAD"}}
{"event_id":"e2","label":"attack","fields":{"path":"/private/report.csv","auth_state":"anonymous","method":"GET"}}
{"event_id":"e3","label":"benign","fields":{"path":"/private/legacy.csv","auth_state":"authenticated","method":"HEAD"}}
{"event_id":"e4","label":"benign","fields":{"path":"/docs/start","auth_state":"anonymous","method":"GET"}}`}
}
func TestHeldOutCountsAndNoInventedTiming(t *testing.T) {
	in := fixtureInput()
	out, err := Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	baseline, candidate := out.EvaluationComparison.Baseline, out.EvaluationComparison.Candidate
	if baseline.TP != 1 || baseline.FP != 1 || baseline.TN != 1 || baseline.FN != 1 {
		t.Fatalf("baseline: %+v", baseline)
	}
	if candidate.TP != 2 || candidate.FP != 0 || candidate.TN != 2 || candidate.FN != 0 {
		t.Fatalf("candidate: %+v", candidate)
	}
	if *baseline.Precision != 0.5 || *baseline.Recall != 0.5 || *baseline.FalsePositiveRate != 0.5 || *candidate.Accuracy != 1 {
		t.Fatalf("rates: %+v %+v", baseline, candidate)
	}
	if baseline.MTTDSeconds != nil || candidate.MTTDSeconds != nil || len(out.Evidence) != 4 || out.Scope != "offline_labeled_rule_evaluation" {
		t.Fatal("claimed timing or live evidence")
	}
	if len(out.Tuning.SHA256) != 64 || out.Evaluation.SHA256 != Hash([]byte(in.EvaluationLogs)) {
		t.Fatal("wrong provenance")
	}
}
func TestTuningAndEvaluationLeakageRejected(t *testing.T) {
	for _, evaluation := range []string{
		`{"event_id":"t1","label":"attack","fields":{"path":"different"}}`,
		`{"event_id":"new","label":"benign","fields":{"method":"GET","auth_state":"anonymous","path":"/private/legacy.csv"},"occurred_at":"2026-10-10T01:00:00Z"}`,
	} {
		in := fixtureInput()
		in.EvaluationLogs = evaluation
		if _, err := Evaluate(in); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overlap accepted: %v", err)
		}
	}
}
func TestMissingFieldsUnknownAndDecisiveFalse(t *testing.T) {
	in := fixtureInput()
	in.EvaluationLogs = `{"event_id":"u1","label":"attack","fields":{"path":"/private/new.csv"}}
{"event_id":"u2","label":"benign","fields":{"path":"/docs/guide"}}`
	out, err := Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	candidate := out.EvaluationComparison.Candidate
	if candidate.UnknownAttack != 1 || candidate.FN != 0 || candidate.TN != 1 || candidate.Recall != nil || candidate.Accuracy != nil || candidate.FalsePositiveRate == nil {
		t.Fatalf("unknown distorted counts: %+v", candidate)
	}
	if len(out.NextValidationPriorities) != 1 || out.NextValidationPriorities[0].Kind != "missing_fields" || out.Evidence[0].MissingFields[0] != "auth_state" {
		t.Fatalf("evidence: %+v", out)
	}
}
func TestUndefinedRatesRemainNull(t *testing.T) {
	in := fixtureInput()
	in.EvaluationLogs = `{"event_id":"only","label":"benign","fields":{"path":"/docs/only","auth_state":"anonymous"}}`
	out, err := Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	candidate := out.EvaluationComparison.Candidate
	if candidate.Precision != nil || candidate.Recall != nil || candidate.FalsePositiveRate == nil || *candidate.FalsePositiveRate != 0 {
		t.Fatalf("undefined rates: %+v", candidate)
	}
	raw, _ := json.Marshal(candidate)
	if !strings.Contains(string(raw), `"precision":null`) {
		t.Fatal("undefined serialized as zero")
	}
}
func TestIndependentActualTimestampsOnly(t *testing.T) {
	in := fixtureInput()
	in.EvaluationLogs = `{"event_id":"timed","label":"attack","fields":{"path":"/private/legacy.csv","auth_state":"anonymous","method":"OPTIONS"},"occurred_at":"2026-10-10T01:00:00Z","baseline_alert_at":"2026-10-10T01:00:12Z","candidate_alert_at":"2026-10-10T01:00:07Z"}`
	out, err := Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.EvaluationComparison.Baseline.MTTDSeconds != nil {
		t.Fatal("unconfirmed times accepted")
	}
	in.TimestampProvenanceConfirmed = true
	out, err = Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	if *out.EvaluationComparison.Baseline.MTTDSeconds != 12 || *out.EvaluationComparison.Candidate.MTTDSeconds != 7 {
		t.Fatalf("separate times lost: %+v", out)
	}
	in.EvaluationLogs = strings.Replace(in.EvaluationLogs, `,"candidate_alert_at":"2026-10-10T01:00:07Z"`, "", 1)
	out, err = Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.EvaluationComparison.Candidate.MTTDSeconds != nil {
		t.Fatal("missing timestamps fabricated")
	}
	in.EvaluationLogs = strings.Replace(in.EvaluationLogs, "01:00:12Z", "00:59:59Z", 1)
	if _, err := Evaluate(in); !errors.Is(err, ErrInvalid) {
		t.Fatal("negative detection delay accepted")
	}
}
func TestSuggestionUsesOnlyTuningAndCopiesRule(t *testing.T) {
	in := fixtureInput()
	before, _ := json.Marshal(in.BaselineRule)
	proposal, err := Suggest(in.TuningLogs, in.BaselineRule)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(in.BaselineRule)
	if string(before) != string(after) {
		t.Fatal("caller baseline mutated")
	}
	if len(proposal.AddedConditions) != 1 || len(proposal.CandidateRule.Any) != 2 || proposal.Tuning.SHA256 != Hash([]byte(in.TuningLogs)) {
		t.Fatalf("proposal: %+v", proposal)
	}
	if _, err := Evaluate(Input{Scenario: in.Scenario, BaselineRule: in.BaselineRule, CandidateRule: proposal.CandidateRule, TuningLogs: in.TuningLogs, EvaluationLogs: in.EvaluationLogs}); err != nil {
		t.Fatal(err)
	}
}
func TestInvalidRuleDatasetAndBounds(t *testing.T) {
	in := fixtureInput()
	invalidRules := []Rule{{Name: "empty"}, {Name: "emptybranch", Any: []Branch{{}}}, {Name: "bad op", Any: []Branch{{All: []Condition{{Field: "path", Op: "exec", Value: "x"}}}}}, {Name: "label leakage", Any: []Branch{{All: []Condition{{Field: "label", Op: "equals", Value: "attack"}}}}}, {Name: "empty value", Any: []Branch{{All: []Condition{{Field: "path", Op: "contains"}}}}}}
	for _, rule := range invalidRules {
		if err := ValidateRule(rule); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad rule accepted: %+v %v", rule, err)
		}
	}
	invalidData := []string{"", `null`, `{"event_id":"1","label":"malicious","fields":{"path":"x"}}`, `{"event_id":"1","label":"attack","fields":{"path":null}}`, `{"event_id":"1","label":"attack","fields":{"path":[]}}`, `{"event_id":"1","label":"attack","fields":{"path":"x"},"extra":true}`, `{"event_id":"1","label":"attack","fields":{"path":"x"}}
{"event_id":"1","label":"benign","fields":{"path":"y"}}`, `{"event_id":"1","label":"attack","fields":{"path":"x"}}
{"event_id":"2","label":"attack","fields":{"path":"x"}}`, strings.Repeat("x", MaxCombinedBytes+1)}
	for _, raw := range invalidData {
		if _, err := ParseDataset(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad data accepted: %.100s %v", raw, err)
		}
	}
	in.TuningLogs = strings.Repeat("x", MaxCombinedBytes)
	in.EvaluationLogs = "x"
	if _, err := Evaluate(in); !errors.Is(err, ErrInvalid) {
		t.Fatal("combined byte bound accepted")
	}
}

func TestDuplicateAndReservedLabelMetadataRejected(t *testing.T) {
	for _, raw := range []string{
		`{"event_id":"1","label":"benign","label":"attack","fields":{"path":"x"}}`,
		`{"event_id":"1","label":"attack","fields":{"LABEL":"attack","path":"x"}}`,
		`{"event_id":"1","label":"attack","fields":{"path":"x","path":"y"}}`,
	} {
		if _, err := ParseDataset(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ambiguous labeling accepted: %v", err)
		}
	}
	for _, field := range []string{"LABEL", "Event_ID", "Ground_Truth", "baseline_alert_at", "Occurred_At"} {
		rule := Rule{Name: "leak", Any: []Branch{{All: []Condition{{Field: field, Op: "equals", Value: "attack"}}}}}
		if err := ValidateRule(rule); !errors.Is(err, ErrInvalid) {
			t.Fatalf("label metadata searchable: %s", field)
		}
	}
}
func TestSuggestionNoControlClassAndBoundedBranches(t *testing.T) {
	in := fixtureInput()
	attackOnly := strings.Split(in.TuningLogs, "\n")[1]
	suggestion, err := Suggest(attackOnly, in.BaselineRule)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestion.AddedConditions) != 0 || len(suggestion.UnresolvedEventIDs) != 1 {
		t.Fatal("proposed candidate without normal controls")
	}
	logs := []string{`{"event_id":"normal","label":"benign","fields":{"path":"/docs","kind":"normal"}}`}
	for i := 0; i < 40; i++ {
		logs = append(logs, fmt.Sprintf(`{"event_id":"attack-%d","label":"attack","fields":{"path":"/private/%d","kind":"attack-%d"}}`, i, i, i))
	}
	suggestion, err = Suggest(strings.Join(logs, "\n"), in.BaselineRule)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestion.AddedConditions) != 8 || len(suggestion.CandidateRule.Any) != 9 || len(suggestion.UnresolvedEventIDs) != 32 {
		t.Fatalf("branch budget not honored: %+v", suggestion)
	}
}

func TestUTF8BOMPreservesUploadedByteHash(t *testing.T) {
	raw := "\ufeff" + `{"event_id":"bom","label":"benign","fields":{"path":"/docs"}}`
	data, err := ParseDataset(raw)
	if err != nil {
		t.Fatal(err)
	}
	if data.Provenance.SHA256 != Hash([]byte(raw)) || data.Provenance.Events != 1 {
		t.Fatal("original UTF-8 bytes lost from provenance")
	}
}

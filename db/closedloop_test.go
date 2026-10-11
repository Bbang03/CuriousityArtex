package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/closedloop"
)

func closedLoopFixture() closedloop.Input {
	rule := closedloop.Rule{Name: "private route", Any: []closedloop.Branch{{All: []closedloop.Condition{{Field: "path", Op: "contains", Value: "/private/", CaseSensitive: true}}}}}
	return closedloop.Input{Scenario: "DB snapshot fixture", BaselineRule: rule, CandidateRule: rule, TuningLogs: `{"event_id":"db-t","label":"attack","fields":{"path":"/private/tuning"}}`, EvaluationLogs: `{"event_id":"db-e","label":"benign","fields":{"path":"/docs/evaluation"}}`}
}
func TestClosedLoopImmutableSnapshotExportAndReferences(t *testing.T) {
	pg, findingID := purpleDB(t)
	in := closedLoopFixture()
	in.FindingID = findingID
	out, err := pg.SaveClosedLoopIteration(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM closed_loop_iterations WHERE id=$1`, out.ID) })
	if out.ID <= 0 || out.CreatedAt.IsZero() || out.Input.TuningLogs != "" || len(out.FindingSnapshot) != 0 {
		t.Fatalf("record: %+v", out)
	}
	originalRow, err := pg.GetClosedLoopIteration(t.Context(), out.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	original := string(originalRow.FindingSnapshot)
	if _, err := pg.Exec(`UPDATE findings SET evidence='changed after iteration' WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	exported, err := pg.GetClosedLoopIteration(t.Context(), out.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Input.TuningLogs != in.TuningLogs || exported.Input.EvaluationLogs != in.EvaluationLogs || string(exported.FindingSnapshot) != original {
		t.Fatal("snapshot or raw evidence changed")
	}
	result, err := closedloop.Evaluate(exported.Input)
	if err != nil {
		t.Fatal(err)
	}
	raw1, _ := json.Marshal(result)
	raw2, _ := json.Marshal(exported.Result)
	if string(raw1) != string(raw2) {
		t.Fatal("export replay differs from persisted result")
	}
	list, err := pg.ListClosedLoopIterations(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range list {
		if item.ID == out.ID {
			found = true
			if item.Evaluation.SHA256 != result.Evaluation.SHA256 {
				t.Fatal("summary provenance")
			}
		}
	}
	if !found {
		t.Fatal("missing history")
	}
	if _, err := pg.GetClosedLoopIteration(t.Context(), -1, true); !errors.Is(err, ErrClosedLoopNotFound) {
		t.Fatalf("missing: %v", err)
	}
	in.FindingID = 9223372036854775807
	if _, err := pg.SaveClosedLoopIteration(t.Context(), in); !errors.Is(err, closedloop.ErrInvalid) {
		t.Fatalf("invalid finding reference: %v", err)
	}
	in.FindingID = 0
	in.CaseID = 9223372036854775807
	if _, err := pg.SaveClosedLoopIteration(t.Context(), in); !errors.Is(err, closedloop.ErrInvalid) {
		t.Fatalf("invalid case reference: %v", err)
	}
}
func TestClosedLoopCannotPersistClientVerdictOrInvalidInputs(t *testing.T) {
	pg, _ := purpleDB(t)
	in := closedLoopFixture()
	in.EvaluationLogs = in.TuningLogs
	if _, err := pg.SaveClosedLoopIteration(t.Context(), in); !errors.Is(err, closedloop.ErrInvalid) {
		t.Fatalf("leaked data accepted: %v", err)
	}
	if _, err := pg.ListClosedLoopIterations(t.Context(), 101); !errors.Is(err, closedloop.ErrInvalid) {
		t.Fatalf("bad bound: %v", err)
	}
}

func TestClosedLoopLinkedRawSnapshotsOnlyInExplicitExport(t *testing.T) {
	pg, findingID := purpleDB(t)
	const sentinel = "closed-loop-raw-private-evidence-sentinel"
	if _, err := pg.Exec(`UPDATE findings SET evidence=$1 WHERE id=$2`, sentinel, findingID); err != nil {
		t.Fatal(err)
	}
	caseInput := defensiveCaseInput(t)
	caseInput.Collection.Files[0].Content += "\n" + sentinel
	c, err := pg.SaveDefensiveCase(t.Context(), caseInput)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM defensive_cases WHERE id=$1`, c.ID) })
	in := closedLoopFixture()
	in.FindingID = findingID
	in.CaseID = c.ID
	saved, err := pg.SaveClosedLoopIteration(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM closed_loop_iterations WHERE id=$1`, saved.ID) })
	raw, _ := json.Marshal(saved)
	if strings.Contains(string(raw), sentinel) || strings.Contains(string(raw), "finding_snapshot") || strings.Contains(string(raw), "case_snapshot") {
		t.Fatal("save leaked linked raw evidence")
	}
	normal, err := pg.GetClosedLoopIteration(t.Context(), saved.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(normal)
	if strings.Contains(string(raw), sentinel) {
		t.Fatal("normal detail leaked original logs")
	}
	list, err := pg.ListClosedLoopIterations(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(list)
	if strings.Contains(string(raw), sentinel) {
		t.Fatal("history leaked original logs")
	}
	exported, err := pg.GetClosedLoopIteration(t.Context(), saved.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(exported)
	if !strings.Contains(string(raw), sentinel) {
		t.Fatal("explicit export lost source snapshot")
	}
}

// Summary history must remain independent of potentially large or differently
// versioned input/evidence payloads. Only the saved evaluation belongs in a list.
func TestClosedLoopHistoryOnlyNeedsBoundedEvaluationSummary(t *testing.T) {
	pg, _ := purpleDB(t)
	in := closedLoopFixture()
	result, err := closedloop.Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"input":         "opaque differently versioned source input",
		"case_snapshot": map[string]any{"collection": map[string]any{"files": []map[string]any{{"content": strings.Repeat("large-private-evidence-", 100000)}}}},
		"result":        map[string]any{"evaluation_comparison": result.EvaluationComparison, "evaluation": result.Evaluation},
	})
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := pg.QueryRow(`INSERT INTO closed_loop_iterations(scenario,payload,tuning_logs,evaluation_logs) VALUES($1,$2,'','') RETURNING id`, "Projected history fixture", payload).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM closed_loop_iterations WHERE id=$1`, id) })
	list, err := pg.ListClosedLoopIterations(t.Context(), 100)
	if err != nil {
		t.Fatalf("history tried to decode unrelated source evidence: %v", err)
	}
	found := false
	for _, summary := range list {
		if summary.ID == id {
			found = true
			if summary.Comparison.Candidate.TN != 1 || summary.Evaluation.SHA256 != result.Evaluation.SHA256 {
				t.Fatalf("wrong projected summary: %+v", summary)
			}
		}
	}
	if !found {
		t.Fatal("missing projected history")
	}
}

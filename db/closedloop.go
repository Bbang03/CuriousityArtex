package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/closedloop"
)

var ErrClosedLoopNotFound = errors.New("Closed-loop 반복 기록을 찾을 수 없습니다")

type ClosedLoopIteration struct {
	ID              int64              `json:"id,string"`
	Input           closedloop.Input   `json:"input"`
	Result          *closedloop.Result `json:"result"`
	FindingSnapshot json.RawMessage    `json:"finding_snapshot,omitempty"`
	CaseSnapshot    json.RawMessage    `json:"case_snapshot,omitempty"`
	CreatedAt       time.Time          `json:"created_at"`
}
type ClosedLoopSummary struct {
	ID         int64                 `json:"id,string"`
	Scenario   string                `json:"scenario"`
	FindingID  int64                 `json:"finding_id,string,omitempty"`
	CaseID     int64                 `json:"case_id,string,omitempty"`
	Comparison closedloop.Comparison `json:"comparison"`
	Evaluation closedloop.Provenance `json:"evaluation"`
	CreatedAt  time.Time             `json:"created_at"`
}

// Save recomputes metrics from input; a caller cannot persist invented verdicts.
// Snapshots and raw datasets remain immutable even if linked evidence changes.
func (d *DB) SaveClosedLoopIteration(ctx context.Context, in closedloop.Input) (*ClosedLoopIteration, error) {
	in.Scenario = strings.TrimSpace(in.Scenario)
	result, err := closedloop.Evaluate(in)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := &ClosedLoopIteration{Input: in, Result: result}
	if in.FindingID > 0 {
		var snapshot []byte
		err = tx.QueryRowContext(ctx, `SELECT jsonb_build_object('id',f.id::text,'name',f.name,'vuln_class',f.vulnclass,'severity',f.severity,'summary',f.summary,'evidence',f.evidence,'evidence_version',f.evidence_version) FROM findings f WHERE f.id=$1 FOR SHARE`, in.FindingID).Scan(&snapshot)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: 연결할 취약점을 찾을 수 없습니다", closedloop.ErrInvalid)
		}
		if err != nil {
			return nil, err
		}
		out.FindingSnapshot = snapshot
	}
	if in.CaseID > 0 {
		var snapshot []byte
		err = tx.QueryRowContext(ctx, `SELECT payload FROM defensive_cases WHERE id=$1 FOR SHARE`, in.CaseID).Scan(&snapshot)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: 연결할 방어 사건을 찾을 수 없습니다", closedloop.ErrInvalid)
		}
		if err != nil {
			return nil, err
		}
		out.CaseSnapshot = snapshot
	}
	// Raw evidence is absent from normal list/detail output. Explicit export owns it.
	out.Input.TuningLogs = ""
	out.Input.EvaluationLogs = ""
	payload, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	var findingID, caseID any
	if in.FindingID > 0 {
		findingID = in.FindingID
	}
	if in.CaseID > 0 {
		caseID = in.CaseID
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO closed_loop_iterations(scenario,finding_id,case_id,payload,tuning_logs,evaluation_logs) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,created_at`, in.Scenario, findingID, caseID, payload, in.TuningLogs, in.EvaluationLogs).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return previewClosedLoopIteration(out), nil
}
func (d *DB) ListClosedLoopIterations(ctx context.Context, limit int) ([]ClosedLoopSummary, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: 표시 개수는 1~100이어야 합니다", closedloop.ErrInvalid)
	}
	rows, err := d.QueryContext(ctx, `SELECT id,scenario,COALESCE(finding_id,0),COALESCE(case_id,0),payload#>'{result,evaluation_comparison}',payload#>'{result,evaluation}',created_at FROM closed_loop_iterations ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClosedLoopSummary{}
	for rows.Next() {
		var summary ClosedLoopSummary
		// A linked case can include many MiB of raw evidence. Project only the
		// two bounded summary objects, never transfer/decode the source snapshot.
		var comparisonJSON, evaluationJSON []byte
		if err := rows.Scan(&summary.ID, &summary.Scenario, &summary.FindingID, &summary.CaseID, &comparisonJSON, &evaluationJSON, &summary.CreatedAt); err != nil {
			return nil, err
		}
		var comparison *closedloop.Comparison
		var evaluation *closedloop.Provenance
		if len(comparisonJSON) == 0 || len(evaluationJSON) == 0 {
			return nil, errors.New("closed-loop record missing evaluation summary")
		}
		if err := json.Unmarshal(comparisonJSON, &comparison); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(evaluationJSON, &evaluation); err != nil {
			return nil, err
		}
		if comparison == nil || evaluation == nil {
			return nil, errors.New("closed-loop record missing evaluation summary")
		}
		summary.Comparison = *comparison
		summary.Evaluation = *evaluation
		out = append(out, summary)
	}
	return out, rows.Err()
}
func (d *DB) GetClosedLoopIteration(ctx context.Context, id int64, export bool) (*ClosedLoopIteration, error) {
	var payload []byte
	var recordID int64
	var created time.Time
	var tuning, evaluation string
	query := `SELECT id,payload,created_at FROM closed_loop_iterations WHERE id=$1`
	args := []any{&recordID, &payload, &created}
	if export {
		query = `SELECT id,payload,created_at,tuning_logs,evaluation_logs FROM closed_loop_iterations WHERE id=$1`
		args = append(args, &tuning, &evaluation)
	}
	if err := d.QueryRowContext(ctx, query, id).Scan(args...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClosedLoopNotFound
		}
		return nil, err
	}
	out := &ClosedLoopIteration{}
	if err := json.Unmarshal(payload, out); err != nil {
		return nil, err
	}
	out.ID = recordID
	out.CreatedAt = created
	if export {
		out.Input.TuningLogs = tuning
		out.Input.EvaluationLogs = evaluation
	}
	if !export {
		return previewClosedLoopIteration(out), nil
	}
	return out, nil
}

// Detailed source snapshots can contain original logs and finding evidence.
// Keep them in the immutable stored payload and authenticated export only.
func previewClosedLoopIteration(record *ClosedLoopIteration) *ClosedLoopIteration {
	preview := *record
	preview.FindingSnapshot = nil
	preview.CaseSnapshot = nil
	preview.Input.TuningLogs = ""
	preview.Input.EvaluationLogs = ""
	return &preview
}

package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrDefensiveCaseRunNotFound = errors.New("침해 조사 실행을 찾을 수 없습니다")
	ErrDefensiveCaseRunInactive = errors.New("침해 조사 실행이 종료되었거나 아직 시작되지 않았습니다")
)

// Runs refer to immutable, locally collected evidence. They never rewrite the
// base investigation; tool evidence and the model's inferences are separate.
type DefensiveCaseRun struct {
	ID         int64                   `json:"id,string"`
	CaseID     int64                   `json:"case_id,string"`
	Status     string                  `json:"status"`
	Options    json.RawMessage         `json:"options"`
	Events     []DefensiveCaseRunEvent `json:"events"`
	Result     json.RawMessage         `json:"result"`
	Usage      InvestigationRunUsage   `json:"usage"`
	Error      string                  `json:"error"`
	CreatedAt  time.Time               `json:"created_at"`
	StartedAt  *time.Time              `json:"started_at"`
	FinishedAt *time.Time              `json:"finished_at"`
	UpdatedAt  time.Time               `json:"updated_at"`
}

type DefensiveCaseRunEvent struct {
	Sequence  int             `json:"sequence"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}

type DefensiveCaseRunSummary struct {
	ID         int64                 `json:"id,string"`
	CaseID     int64                 `json:"case_id,string"`
	Status     string                `json:"status"`
	Usage      InvestigationRunUsage `json:"usage"`
	Error      string                `json:"error"`
	CreatedAt  time.Time             `json:"created_at"`
	StartedAt  *time.Time            `json:"started_at"`
	FinishedAt *time.Time            `json:"finished_at"`
	UpdatedAt  time.Time             `json:"updated_at"`
}

const defensiveCaseRunCols = `id,case_id,status,options,events,result,rounds,model_calls,queries,tool_calls,input_tokens,output_tokens,error,created_at,started_at,finished_at,updated_at`

func scanDefensiveCaseRun(row interface{ Scan(...any) error }) (*DefensiveCaseRun, error) {
	r := &DefensiveCaseRun{}
	var events []byte
	err := row.Scan(&r.ID, &r.CaseID, &r.Status, &r.Options, &events, &r.Result,
		&r.Usage.Rounds, &r.Usage.ModelCalls, &r.Usage.Queries, &r.Usage.ToolCalls, &r.Usage.InputTokens, &r.Usage.OutputTokens,
		&r.Error, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDefensiveCaseRunNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(events, &r.Events); err != nil {
		return nil, err
	}
	return r, nil
}

// One active run per case prevents accidental duplicate model/Splunk work.
func (d *DB) CreateDefensiveCaseRun(ctx context.Context, caseID int64, options json.RawMessage) (*DefensiveCaseRun, bool, error) {
	options, err := investigationRunObject(options, 64<<10)
	if err != nil {
		return nil, false, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	var locked int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM defensive_cases WHERE id=$1 FOR UPDATE`, caseID).Scan(&locked); errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrDefensiveCaseNotFound
	} else if err != nil {
		return nil, false, err
	}
	existing, err := scanDefensiveCaseRun(tx.QueryRowContext(ctx, `SELECT `+defensiveCaseRunCols+` FROM defensive_case_runs WHERE case_id=$1 AND status IN ('queued','running')`, caseID))
	if err == nil {
		return existing, false, tx.Commit()
	}
	if !errors.Is(err, ErrDefensiveCaseRunNotFound) {
		return nil, false, err
	}
	out, err := scanDefensiveCaseRun(tx.QueryRowContext(ctx, `INSERT INTO defensive_case_runs(case_id,options) VALUES($1,$2) RETURNING `+defensiveCaseRunCols, caseID, options))
	if err != nil {
		return nil, false, err
	}
	return out, true, tx.Commit()
}

func (d *DB) StartDefensiveCaseRun(ctx context.Context, id int64) (bool, error) {
	result, err := d.ExecContext(ctx, `UPDATE defensive_case_runs SET status='running',started_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND status='queued'`, id)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// Append is atomic and bounded. Previously saved query responses retain their
// evidence references, bytes, and timestamps even if a later model call fails.
func (d *DB) AppendDefensiveCaseRunEvent(ctx context.Context, id int64, kind string, payload json.RawMessage, usage InvestigationRunUsage) (*DefensiveCaseRunEvent, error) {
	kind = strings.TrimSpace(kind)
	if len(kind) == 0 || len(kind) > 80 || !usage.valid() {
		return nil, ErrDefenseInvalid
	}
	payload, err := investigationRunObject(payload, 16<<20)
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var status string
	var count, size int
	var previous InvestigationRunUsage
	err = tx.QueryRowContext(ctx, `SELECT status,jsonb_array_length(events),octet_length(events::text)+octet_length(options::text),rounds,model_calls,queries,tool_calls,input_tokens,output_tokens FROM defensive_case_runs WHERE id=$1 FOR UPDATE`, id).
		Scan(&status, &count, &size, &previous.Rounds, &previous.ModelCalls, &previous.Queries, &previous.ToolCalls, &previous.InputTokens, &previous.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDefensiveCaseRunNotFound
	}
	if err != nil {
		return nil, err
	}
	if status != "running" {
		return nil, ErrDefensiveCaseRunInactive
	}
	if !usage.contains(previous) {
		return nil, fmt.Errorf("%w: 조사 실행 사용량은 감소할 수 없습니다", ErrDefenseInvalid)
	}
	out := &DefensiveCaseRunEvent{Sequence: count + 1, Kind: kind, Payload: payload}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&out.CreatedAt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal([]DefensiveCaseRunEvent{*out})
	if err != nil {
		return nil, err
	}
	if count >= 256 || size+len(raw) > 24<<20 {
		return nil, fmt.Errorf("%w: 조사 실행 기록 저장 한도에 도달했습니다", ErrDefenseInvalid)
	}
	_, err = tx.ExecContext(ctx, `UPDATE defensive_case_runs SET events=events || $2::jsonb,rounds=$3,tool_calls=$4,input_tokens=$5,output_tokens=$6,updated_at=$7,model_calls=$8,queries=$9 WHERE id=$1`, id, raw, usage.Rounds, usage.ToolCalls, usage.InputTokens, usage.OutputTokens, out.CreatedAt, usage.ModelCalls, usage.Queries)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// A terminal run is sealed. A late worker cannot overwrite cancellation or a
// restart interruption, and cannot replace a previously recorded conclusion.
func (d *DB) FinishDefensiveCaseRun(ctx context.Context, id int64, status string, result json.RawMessage, errorMessage string, usage InvestigationRunUsage) (bool, error) {
	if !investigationRunTerminal(status) || !usage.valid() {
		return false, ErrDefenseInvalid
	}
	result, err := investigationRunObject(result, 32<<20)
	if err != nil {
		return false, err
	}
	if errorMessage, err = defenseText(errorMessage, "조사 실행 오류", 0, 8000); err != nil {
		return false, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var previous InvestigationRunUsage
	var previousStatus string
	var size int
	err = tx.QueryRowContext(ctx, `SELECT status,octet_length(events::text)+octet_length(options::text),rounds,model_calls,queries,tool_calls,input_tokens,output_tokens FROM defensive_case_runs WHERE id=$1 FOR UPDATE`, id).
		Scan(&previousStatus, &size, &previous.Rounds, &previous.ModelCalls, &previous.Queries, &previous.ToolCalls, &previous.InputTokens, &previous.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrDefensiveCaseRunNotFound
	}
	if err != nil {
		return false, err
	}
	if investigationRunTerminal(previousStatus) {
		return false, nil
	}
	if !usage.contains(previous) || size+len(result) > 24<<20 {
		return false, fmt.Errorf("%w: 조사 실행 사용량 또는 저장 한도를 확인해 주세요", ErrDefenseInvalid)
	}
	_, err = tx.ExecContext(ctx, `UPDATE defensive_case_runs SET status=$2,result=$3,error=$4,rounds=$5,tool_calls=$6,input_tokens=$7,output_tokens=$8,model_calls=$9,queries=$10,finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, id, status, result, errorMessage, usage.Rounds, usage.ToolCalls, usage.InputTokens, usage.OutputTokens, usage.ModelCalls, usage.Queries)
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (d *DB) CancelDefensiveCaseRun(ctx context.Context, caseID, id int64) (*DefensiveCaseRun, error) {
	_, err := d.ExecContext(ctx, `UPDATE defensive_case_runs SET status='cancelled',error='사용자가 조사를 중단했습니다',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE case_id=$1 AND id=$2 AND status IN ('queued','running')`, caseID, id)
	if err != nil {
		return nil, err
	}
	return d.GetDefensiveCaseRun(ctx, caseID, id)
}

// Call once before accepting work after a process restart. Partial evidence is
// retained; interrupted work is never silently restarted and charged again.
func (d *DB) RecoverDefensiveCaseRuns(ctx context.Context) (int64, error) {
	result, err := d.ExecContext(ctx, `UPDATE defensive_case_runs SET status='interrupted',error='서비스 재시작으로 조사가 중단되었습니다. 저장된 근거를 확인한 뒤 다시 시작해 주세요',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE status IN ('queued','running')`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (d *DB) GetDefensiveCaseRun(ctx context.Context, caseID, id int64) (*DefensiveCaseRun, error) {
	return scanDefensiveCaseRun(d.QueryRowContext(ctx, `SELECT `+defensiveCaseRunCols+` FROM defensive_case_runs WHERE case_id=$1 AND id=$2`, caseID, id))
}

// Lists the case's latest 30 runs.
// Summaries intentionally omit options, raw tool evidence, and model output.
func (d *DB) ListDefensiveCaseRuns(ctx context.Context, caseID int64) ([]DefensiveCaseRunSummary, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,case_id,status,rounds,model_calls,queries,tool_calls,input_tokens,output_tokens,error,created_at,started_at,finished_at,updated_at FROM defensive_case_runs WHERE case_id=$1 ORDER BY id DESC LIMIT 30`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DefensiveCaseRunSummary{}
	for rows.Next() {
		var r DefensiveCaseRunSummary
		if err = rows.Scan(&r.ID, &r.CaseID, &r.Status,
			&r.Usage.Rounds, &r.Usage.ModelCalls, &r.Usage.Queries, &r.Usage.ToolCalls, &r.Usage.InputTokens, &r.Usage.OutputTokens,
			&r.Error, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

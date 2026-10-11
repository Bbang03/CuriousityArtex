package db

import (
	"context"
	"time"
)

// AegisOverview describes recorded work, never estimated detection accuracy.
// Performance ratios belong to a specific labeled closed-loop evaluation.
type AegisOverview struct {
	Offensive struct {
		Tasks       int64 `json:"tasks"`
		ActiveTasks int64 `json:"active_tasks"`
		Findings    int64 `json:"findings"`
		Assets      int64 `json:"assets"`
	} `json:"offensive"`
	Defensive struct {
		Cases          int64 `json:"cases"`
		ActiveRuns     int64 `json:"active_runs"`
		Sources        int64 `json:"sources"`
		ObservedEvents int64 `json:"observed_events"`
	} `json:"defensive"`
	ClosedLoop struct {
		Cycles int64 `json:"cycles"`
	} `json:"closed_loop"`
	GeneratedAt time.Time `json:"generated_at"`
}

func (d *DB) GetAegisOverview(ctx context.Context) (*AegisOverview, error) {
	out := &AegisOverview{}
	// One statement provides a consistent MVCC snapshot across all engines.
	err := d.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM tasks WHERE deleted_at IS NULL AND archived_at IS NULL),
 (SELECT count(*) FROM tasks WHERE deleted_at IS NULL AND archived_at IS NULL AND status='running' AND NOT paused),
 (SELECT count(*) FROM findings),
 (SELECT count(*) FROM assets),
 (SELECT count(*) FROM defensive_cases),
 (SELECT count(*) FROM defensive_case_runs WHERE status IN ('queued','running')),
 (SELECT count(*) FROM security_sources WHERE enabled AND octet_length(secret_cipher)>0),
 (SELECT COALESCE(sum((payload#>>'{analysis,observed_count}')::bigint),0) FROM defensive_cases),
 (SELECT count(*) FROM closed_loop_iterations),
 statement_timestamp()`).Scan(
		&out.Offensive.Tasks, &out.Offensive.ActiveTasks, &out.Offensive.Findings, &out.Offensive.Assets,
		&out.Defensive.Cases, &out.Defensive.ActiveRuns, &out.Defensive.Sources, &out.Defensive.ObservedEvents,
		&out.ClosedLoop.Cycles, &out.GeneratedAt,
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

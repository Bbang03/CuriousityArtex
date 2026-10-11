package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/offensivereview"
)

var ErrOffensiveReviewConflict = errors.New("offensive review ownership or evidence changed")

// Each scan has one immutable evidence snapshot and checkpointed candidate list.
// The owner lease protects a late model response from overwriting cancellation,
// recovery, or a newer attempt after a process failure.
type OffensiveReview struct {
	RunID          string                     `json:"run_id"`
	Kind           string                     `json:"kind"`
	EvidenceSHA256 string                     `json:"evidence_sha256"`
	LegacyTaskID   string                     `json:"legacy_task_id,omitempty"`
	Status         string                     `json:"status"`
	Reason         string                     `json:"reason"`
	ProfileID      int64                      `json:"profile_id"`
	CreatedAt      time.Time                  `json:"created_at"`
	UpdatedAt      time.Time                  `json:"updated_at"`
	Total          int                        `json:"total"`
	Reviewed       int                        `json:"reviewed"`
	Pending        int                        `json:"pending"`
	Candidates     []OffensiveReviewCandidate `json:"candidates"`
	Attempts       []OffensiveReviewAttempt   `json:"attempts"`
	Owner          string                     `json:"-"`
	LeaseUntil     time.Time                  `json:"-"`
}

type OffensiveReviewCandidate struct {
	offensivereview.Candidate
	Status       string                  `json:"status"`
	Result       *offensivereview.Result `json:"result,omitempty"`
	AttemptCount int                     `json:"attempt_count"`
	LastError    string                  `json:"last_error,omitempty"`
	StartedAt    *time.Time              `json:"started_at,omitempty"`
	FinishedAt   *time.Time              `json:"finished_at,omitempty"`
}

type OffensiveReviewAttempt struct {
	ID              string     `json:"id"`
	Status          string     `json:"status"`
	BatchSize       int        `json:"batch_size"`
	ProfileID       int64      `json:"profile_id"`
	QueuedAt        time.Time  `json:"queued_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	ModelCalls      int        `json:"model_calls"`
	InputTokens     int        `json:"input_tokens"`
	OutputTokens    int        `json:"output_tokens"`
	ModelElapsedMS  int64      `json:"model_elapsed_ms"`
	ActiveElapsedMS int64      `json:"active_elapsed_ms"`
	QueueWaitMS     int64      `json:"queue_wait_ms"`
	Reason          string     `json:"reason,omitempty"`
}

// RecordElapsed uses a live monotonic duration when available. After restart
// only wall timestamps remain; clock adjustments must not make active time
// negative or shorter than the model work already measured and checkpointed.
func (a *OffensiveReviewAttempt) RecordElapsed(now time.Time, activeElapsed *time.Duration) {
	if a.StartedAt != nil {
		elapsed := now.Sub(*a.StartedAt).Milliseconds()
		if activeElapsed != nil {
			elapsed = activeElapsed.Milliseconds()
		}
		a.ActiveElapsedMS = max(0, a.ActiveElapsedMS, a.ModelElapsedMS, elapsed)
	} else {
		a.QueueWaitMS = max(0, a.QueueWaitMS, now.Sub(a.QueuedAt).Milliseconds())
	}
}

func (r *OffensiveReview) RefreshCounts() {
	r.Total, r.Reviewed = len(r.Candidates), 0
	for _, c := range r.Candidates {
		if c.Result != nil {
			r.Reviewed++
		}
	}
	r.Pending = r.Total - r.Reviewed
}

func (d *DB) EnsureOffensiveReview(ctx context.Context, r *OffensiveReview) (*OffensiveReview, error) {
	r.RefreshCounts()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	r.UpdatedAt = r.CreatedAt
	if r.Attempts == nil {
		r.Attempts = []OffensiveReviewAttempt{}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	_, err = d.ExecContext(ctx, `INSERT INTO offensive_candidate_reviews(run_id,document) VALUES($1,$2) ON CONFLICT(run_id) DO NOTHING`, r.RunID, raw)
	if err != nil {
		return nil, err
	}
	existing, err := d.GetOffensiveReview(ctx, r.RunID)
	if err != nil {
		return nil, err
	}
	if existing.Kind != r.Kind || existing.EvidenceSHA256 != r.EvidenceSHA256 {
		return nil, ErrOffensiveReviewConflict
	}
	return existing, nil
}

func readOffensiveReview(row interface{ Scan(...any) error }) (*OffensiveReview, error) {
	var raw []byte
	var owner string
	var lease sql.NullTime
	if err := row.Scan(&raw, &owner, &lease); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	var r OffensiveReview
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	r.Owner, r.LeaseUntil = owner, lease.Time
	r.RefreshCounts()
	return &r, nil
}

func (d *DB) GetOffensiveReview(ctx context.Context, runID string) (*OffensiveReview, error) {
	return readOffensiveReview(d.QueryRowContext(ctx, `SELECT document,owner,lease_until FROM offensive_candidate_reviews WHERE run_id=$1`, runID))
}

// Mutations are serialized in PostgreSQL, including requests arriving at the
// same instant from two tabs. No model call is made under this transaction.
func (d *DB) UpdateOffensiveReview(ctx context.Context, runID string, edit func(*OffensiveReview) error) (*OffensiveReview, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := readOffensiveReview(tx.QueryRowContext(ctx, `SELECT document,owner,lease_until FROM offensive_candidate_reviews WHERE run_id=$1 FOR UPDATE`, runID))
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, sql.ErrNoRows
	}
	if err = edit(r); err != nil {
		return nil, err
	}
	r.RefreshCounts()
	r.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var lease any
	if !r.LeaseUntil.IsZero() {
		lease = r.LeaseUntil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE offensive_candidate_reviews SET document=$2,owner=$3,lease_until=$4 WHERE run_id=$1`, runID, raw, r.Owner, lease); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

func InterruptOffensiveReview(r *OffensiveReview, now time.Time, reason string) {
	r.Status, r.Reason, r.Owner, r.LeaseUntil = "interrupted", reason, "", time.Time{}
	for i := range r.Candidates {
		c := &r.Candidates[i]
		if c.Status == "running" {
			c.Status = "pending"
			c.LastError = reason
		}
	}
	if n := len(r.Attempts); n > 0 {
		a := &r.Attempts[n-1]
		if a.Status == "running" || a.Status == "queued" {
			a.Status, a.Reason, a.FinishedAt = "interrupted", reason, &now
			a.RecordElapsed(now, nil)
		}
	}
}

// Recovery only touches expired leases, never live work when another browser
// polls. Finished candidate verdicts are left intact and can be resumed.
func (d *DB) RecoverOffensiveReview(ctx context.Context, runID string) (*OffensiveReview, error) {
	r, err := d.GetOffensiveReview(ctx, runID)
	if err != nil || r == nil {
		return r, err
	}
	if (r.Status != "running" && r.Status != "queued") || r.LeaseUntil.After(time.Now()) {
		return r, nil
	}
	return d.UpdateOffensiveReview(ctx, runID, func(r *OffensiveReview) error {
		if (r.Status == "running" || r.Status == "queued") && !r.LeaseUntil.After(time.Now()) {
			InterruptOffensiveReview(r, time.Now().UTC(), "서버 실행이 중단되었습니다. 저장된 판정은 유지되며 남은 후보를 이어서 검토할 수 있습니다.")
		}
		return nil
	})
}

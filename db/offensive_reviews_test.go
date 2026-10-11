package db

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/offensivereview"
	"github.com/google/uuid"
)

func offensiveReviewDB(t *testing.T) (*DB, *OffensiveReview) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	r := &OffensiveReview{RunID: uuid.NewString(), Kind: "source", EvidenceSHA256: "immutable-report", Status: "partial", Candidates: []OffensiveReviewCandidate{
		{Candidate: offensivereview.Candidate{ID: "one", Kind: "source", Title: "first", Evidence: []offensivereview.Evidence{{Ref: "source:1", Text: "source excerpt"}}}, Status: "pending"},
		{Candidate: offensivereview.Candidate{ID: "two", Kind: "source", Title: "second"}, Status: "pending"},
	}}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM offensive_candidate_reviews WHERE run_id=$1`, r.RunID); d.Close() })
	got, err := d.EnsureOffensiveReview(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	return d, got
}

func TestOffensiveReviewAtomicClaimAndFrozenEvidence(t *testing.T) {
	d, r := offensiveReviewDB(t)
	var claimed atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, err := d.UpdateOffensiveReview(t.Context(), r.RunID, func(r *OffensiveReview) error {
				if r.Owner != "" {
					return ErrOffensiveReviewConflict
				}
				r.Owner = "winner"
				r.Status = "queued"
				r.LeaseUntil = time.Now().Add(time.Minute)
				return nil
			})
			if err == nil {
				claimed.Add(1)
			} else if !errors.Is(err, ErrOffensiveReviewConflict) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if claimed.Load() != 1 {
		t.Fatal("duplicate jobs admitted", claimed.Load())
	}
	r.EvidenceSHA256 = "changed"
	if _, err := d.EnsureOffensiveReview(t.Context(), r); !errors.Is(err, ErrOffensiveReviewConflict) {
		t.Fatal("changed snapshot accepted", err)
	}
	got, err := d.GetOffensiveReview(t.Context(), r.RunID)
	if err != nil || got.Candidates[0].Evidence[0].Text != "source excerpt" {
		t.Fatal("evidence was not persisted", err)
	}
}

func TestOffensiveReviewRecoveryPreservesCheckpointsAndLiveLease(t *testing.T) {
	d, r := offensiveReviewDB(t)
	now := time.Now().UTC()
	_, err := d.UpdateOffensiveReview(t.Context(), r.RunID, func(r *OffensiveReview) error {
		r.Status, r.Owner, r.LeaseUntil = "running", "first", now.Add(time.Minute)
		r.Candidates[0].Status = "rejected"
		r.Candidates[0].Result = &offensivereview.Result{CandidateID: "one", Status: "rejected", Summary: "not a defect"}
		r.Candidates[1].Status = "running"
		r.Attempts = []OffensiveReviewAttempt{{ID: "attempt1", Status: "running", StartedAt: &now}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	live, err := d.RecoverOffensiveReview(t.Context(), r.RunID)
	if err != nil || live.Status != "running" || live.Owner != "first" {
		t.Fatal("poll interrupted live work", err)
	}
	_, err = d.UpdateOffensiveReview(t.Context(), r.RunID, func(r *OffensiveReview) error { r.LeaseUntil = now.Add(-time.Minute); return nil })
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.RecoverOffensiveReview(t.Context(), r.RunID)
	if err != nil || got.Status != "interrupted" || got.Owner != "" || got.Reviewed != 1 || got.Pending != 1 || got.Candidates[1].Status != "pending" || got.Candidates[0].Result.Summary != "not a defect" || got.Attempts[0].Status != "interrupted" {
		t.Fatalf("bad recovery %+v %v", got, err)
	}
	_, err = d.UpdateOffensiveReview(t.Context(), r.RunID, func(r *OffensiveReview) error {
		if r.Owner != "first" {
			return ErrOffensiveReviewConflict
		}
		t.Error("late worker admitted")
		return nil
	})
	if !errors.Is(err, ErrOffensiveReviewConflict) {
		t.Fatal("late completion was accepted", err)
	}
}

func TestOffensiveReviewElapsedSurvivesWallClockAdjustment(t *testing.T) {
	start := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{-2 * time.Second, 2 * time.Second} {
		a := OffensiveReviewAttempt{StartedAt: &start, ModelElapsedMS: 4665}
		a.RecordElapsed(start.Add(offset), nil)
		if a.ActiveElapsedMS != 4665 {
			t.Fatalf("wall adjustment %s produced %dms shorter than measured model work", offset, a.ActiveElapsedMS)
		}
	}
	a := OffensiveReviewAttempt{StartedAt: &start, ModelElapsedMS: 4665}
	monotonicElapsed := 5 * time.Second
	a.RecordElapsed(start.Add(time.Hour), &monotonicElapsed)
	if a.ActiveElapsedMS != 5000 {
		t.Fatal("normal completion used adjusted wall time instead of monotonic duration", a.ActiveElapsedMS)
	}
	a.RecordElapsed(start.Add(-time.Hour), nil)
	if a.ActiveElapsedMS != 5000 {
		t.Fatal("recovery shrank an already measured active duration", a.ActiveElapsedMS)
	}
	queued := OffensiveReviewAttempt{QueuedAt: start}
	queued.RecordElapsed(start.Add(-time.Second), nil)
	if queued.QueueWaitMS != 0 {
		t.Fatal("negative queue duration", queued.QueueWaitMS)
	}
	review := OffensiveReview{Attempts: []OffensiveReviewAttempt{{Status: "running", StartedAt: &start, ModelElapsedMS: 4665}}}
	InterruptOffensiveReview(&review, start.Add(-time.Second), "restart")
	if review.Attempts[0].ActiveElapsedMS != 4665 {
		t.Fatal("cancellation/recovery bypassed duration floor", review.Attempts[0])
	}
}

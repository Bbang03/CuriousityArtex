package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/offensivereview"
	"github.com/Autumn-27/norma/llm"
	"github.com/google/uuid"
)

const offensiveReviewLease = 2 * time.Minute

type offensiveReviewJob struct {
	runID, owner, attemptID string
	ctx                     context.Context
	cancel                  context.CancelFunc
	provider                llm.Provider
	maxTokens               int
	startedAt               time.Time // preserves monotonic clock; never serialized
}

// One FIFO belongs exclusively to candidate reviews: API and source reviews
// cannot compete with each other for the same shared profile rate limiter.
// Existing Planner/Worker and Defensive execution are not changed.
type offensiveReviewRuntime struct {
	mu               sync.Mutex
	queue            []*offensiveReviewJob
	jobs             map[string]*offensiveReviewJob
	pumping          bool
	prepare          func(context.Context, string) (*preparedOffensiveReview, error)
	provider         func(int64) (llm.Provider, agent.Config, bool)
	review           func(context.Context, llm.Provider, offensivereview.Candidate, int) (offensivereview.Result, offensivereview.Metrics, error)
	candidateTimeout time.Duration
}

func (s *Server) offensiveReviews() *offensiveReviewRuntime {
	s.offensiveReviewInitMu.Lock()
	defer s.offensiveReviewInitMu.Unlock()
	if s.offensiveReviewRuntime == nil {
		s.offensiveReviewRuntime = &offensiveReviewRuntime{jobs: map[string]*offensiveReviewJob{}, prepare: s.prepareOffensiveReview, provider: s.providerForProfile, review: offensivereview.Review, candidateTimeout: 300 * time.Second}
	}
	return s.offensiveReviewRuntime
}

func (s *Server) offensiveReviewRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	offensiveHeaders(w)
	if r.URL.RawQuery != "" {
		writeErr(w, 400, "진단 API에는 추가 조회 조건을 전달할 수 없습니다")
		return "", false
	}
	id, err := offensiveRunID(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return "", false
	}
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "진단 검토 저장소가 준비되지 않았습니다")
		return "", false
	}
	return id, true
}

func (s *Server) getOffensiveCandidateReview(w http.ResponseWriter, r *http.Request) {
	id, ok := s.offensiveReviewRequest(w, r)
	if !ok {
		return
	}
	review, err := s.m.pg.RecoverOffensiveReview(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "저장된 후보 검토를 불러오지 못했습니다")
		return
	}
	writeJSON(w, 200, map[string]any{"review": review})
}

func (s *Server) startOffensiveCandidateReview(w http.ResponseWriter, r *http.Request) {
	id, ok := s.offensiveReviewRequest(w, r)
	if !ok {
		return
	}
	var req struct {
		ProfileID int64 `json:"llm_profile_id"`
		BatchSize int   `json:"batch_size"`
	}
	if err := readOffensiveRequest(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.BatchSize == 0 {
		req.BatchSize = 3
	}
	if req.ProfileID < 0 || req.BatchSize < 1 || req.BatchSize > 5 {
		writeErr(w, 400, "검토 후보 수는 1~5개이며 LLM 설정 ID는 양수여야 합니다")
		return
	}
	rt := s.offensiveReviews()
	// Fetch and verify frozen runner artifacts before creating/resuming a job.
	prepared, err := rt.prepare(r.Context(), id)
	if err != nil {
		writeErr(w, 409, "진단 근거를 준비하지 못했습니다: "+err.Error())
		return
	}
	initial := &db.OffensiveReview{RunID: id, Kind: prepared.Kind, EvidenceSHA256: prepared.EvidenceSHA256, LegacyTaskID: prepared.LegacyTaskID, Status: "partial", Candidates: []db.OffensiveReviewCandidate{}}
	for _, c := range prepared.Candidates {
		checkpoint := db.OffensiveReviewCandidate{Candidate: c, Status: "pending"}
		if result, ok := prepared.AutoResults[c.ID]; ok {
			copy := result
			checkpoint.Result = &copy
			checkpoint.Status = result.Status
			now := time.Now().UTC()
			checkpoint.FinishedAt = &now
		}
		initial.Candidates = append(initial.Candidates, checkpoint)
	}
	initial.RefreshCounts()
	if initial.Pending == 0 {
		initial.Status = "completed"
		initial.Reason = "모든 후보의 근거 판정을 저장했습니다."
	}
	current, err := s.m.pg.EnsureOffensiveReview(r.Context(), initial)
	if err != nil {
		if errors.Is(err, db.ErrOffensiveReviewConflict) {
			writeErr(w, 409, "저장된 진단 근거가 변경되었습니다. 새 도구 진단을 실행하세요")
		} else {
			writeErr(w, 500, "후보 검토 근거를 저장하지 못했습니다")
		}
		return
	}
	current, err = s.m.pg.RecoverOffensiveReview(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "저장된 검토 상태를 복구하지 못했습니다")
		return
	}
	if current.Status == "running" || current.Status == "queued" || current.Pending == 0 {
		writeJSON(w, 200, map[string]any{"review": current})
		return
	}
	if req.ProfileID == 0 {
		if current.ProfileID > 0 {
			req.ProfileID = current.ProfileID
		} else if p, _ := s.m.pg.ActiveProfile(); p != nil {
			req.ProfileID = p.ID
		}
	}
	provider, cfg, ok := rt.provider(req.ProfileID)
	if !ok || provider == nil {
		writeErr(w, 400, "사용할 수 있는 LLM 설정을 선택하세요")
		return
	}
	rt.mu.Lock()
	now := time.Now().UTC()
	owner := uuid.NewString()
	attemptID := uuid.NewString()
	current, err = s.m.pg.UpdateOffensiveReview(r.Context(), id, func(review *db.OffensiveReview) error {
		if review.EvidenceSHA256 != prepared.EvidenceSHA256 || review.Status == "running" || review.Status == "queued" || review.Pending == 0 {
			return db.ErrOffensiveReviewConflict
		}
		review.Status, review.Reason, review.ProfileID = "queued", "후보 검토 실행 순서를 기다리고 있습니다.", req.ProfileID
		review.Owner, review.LeaseUntil = owner, now.Add(offensiveReviewLease)
		review.Attempts = append(review.Attempts, db.OffensiveReviewAttempt{ID: attemptID, Status: "queued", BatchSize: req.BatchSize, ProfileID: req.ProfileID, QueuedAt: now})
		return nil
	})
	if err != nil {
		rt.mu.Unlock()
		if errors.Is(err, db.ErrOffensiveReviewConflict) {
			current, _ = s.m.pg.GetOffensiveReview(r.Context(), id)
			writeJSON(w, 200, map[string]any{"review": current})
		} else {
			writeErr(w, 500, "검토 실행을 저장하지 못했습니다")
		}
		return
	}
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	job := &offensiveReviewJob{runID: id, owner: owner, attemptID: attemptID, ctx: ctx, cancel: cancel, provider: provider, maxTokens: cfg.MaxTokens}
	rt.jobs[id] = job
	rt.queue = append(rt.queue, job)
	startPump := !rt.pumping
	rt.pumping = true
	rt.mu.Unlock()
	go s.heartbeatOffensiveReview(job)
	if startPump {
		go s.pumpOffensiveReviews(rt)
	}
	writeJSON(w, 202, map[string]any{"review": current})
}

func (s *Server) cancelOffensiveCandidateReview(w http.ResponseWriter, r *http.Request) {
	id, ok := s.offensiveReviewRequest(w, r)
	if !ok {
		return
	}
	var req struct{}
	if err := readOffensiveRequest(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rt := s.offensiveReviews()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	review, err := s.m.pg.UpdateOffensiveReview(r.Context(), id, func(review *db.OffensiveReview) error {
		if review.Status != "queued" && review.Status != "running" {
			return nil
		}
		now := time.Now().UTC()
		db.InterruptOffensiveReview(review, now, "사용자가 중지했습니다. 완료된 후보는 유지됩니다. 중단된 호출의 토큰 사용량은 확인되지 않아 합계에 포함되지 않을 수 있습니다.")
		review.Status = "cancelled"
		review.RefreshCounts()
		if review.Pending == 0 {
			review.Status, review.Reason = "completed", "모든 후보의 근거 판정을 저장했습니다."
		}
		if len(review.Attempts) > 0 {
			review.Attempts[len(review.Attempts)-1].Status = review.Status
			review.Attempts[len(review.Attempts)-1].Reason = review.Reason
		}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "저장된 검토가 없습니다")
		return
	}
	if err != nil {
		writeErr(w, 500, "검토 중지를 저장하지 못했습니다")
		return
	}
	if job := rt.jobs[id]; job != nil {
		job.cancel()
	}
	writeJSON(w, 200, map[string]any{"review": review})
}

func (s *Server) editOffensiveJob(job *offensiveReviewJob, edit func(*db.OffensiveReview, *db.OffensiveReviewAttempt) error) (*db.OffensiveReview, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.m.pg.UpdateOffensiveReview(ctx, job.runID, func(r *db.OffensiveReview) error {
		if r.Owner != job.owner || len(r.Attempts) == 0 {
			return db.ErrOffensiveReviewConflict
		}
		a := &r.Attempts[len(r.Attempts)-1]
		if a.ID != job.attemptID {
			return db.ErrOffensiveReviewConflict
		}
		return edit(r, a)
	})
}

func (s *Server) heartbeatOffensiveReview(job *offensiveReviewJob) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-job.ctx.Done():
			return
		case <-ticker.C:
			_, err := s.editOffensiveJob(job, func(r *db.OffensiveReview, a *db.OffensiveReviewAttempt) error {
				r.LeaseUntil = time.Now().UTC().Add(offensiveReviewLease)
				return nil
			})
			if err != nil {
				job.cancel()
				return
			}
		}
	}
}

func (s *Server) pumpOffensiveReviews(rt *offensiveReviewRuntime) {
	for {
		rt.mu.Lock()
		if len(rt.queue) == 0 {
			rt.pumping = false
			rt.mu.Unlock()
			return
		}
		job := rt.queue[0]
		rt.queue = rt.queue[1:]
		rt.mu.Unlock()
		s.runOffensiveReview(rt, job)
		job.cancel()
		rt.mu.Lock()
		if rt.jobs[job.runID] == job {
			delete(rt.jobs, job.runID)
		}
		rt.mu.Unlock()
	}
}

func (s *Server) runOffensiveReview(rt *offensiveReviewRuntime, job *offensiveReviewJob) {
	if job.ctx.Err() != nil {
		s.finishOffensiveReview(job, "interrupted", "검토 실행이 중단되었습니다. 남은 후보를 이어서 검토하세요.")
		return
	}
	current, err := s.editOffensiveJob(job, func(r *db.OffensiveReview, a *db.OffensiveReviewAttempt) error {
		job.startedAt = time.Now()
		now := job.startedAt.UTC()
		r.Status, r.Reason = "running", "선택된 후보를 순서대로 검토하고 판정을 즉시 저장합니다."
		a.Status, a.StartedAt = "running", &now
		a.QueueWaitMS = max(0, now.Sub(a.QueuedAt).Milliseconds())
		return nil
	})
	if err != nil {
		return
	}
	a := current.Attempts[len(current.Attempts)-1]
	ids := []string{}
	// New candidates come before retries so a persistently failing candidate
	// cannot starve the rest when the user selects one candidate per batch.
	for _, retry := range []bool{false, true} {
		for _, c := range current.Candidates {
			if c.Result == nil && (c.Status == "error") == retry && len(ids) < a.BatchSize {
				ids = append(ids, c.ID)
			}
		}
	}
	batchCtx, cancel := context.WithTimeout(job.ctx, 25*time.Minute)
	defer cancel()
	var stoppedError error
	for _, id := range ids {
		if batchCtx.Err() != nil {
			break
		}
		var input offensivereview.Candidate
		_, err = s.editOffensiveJob(job, func(r *db.OffensiveReview, a *db.OffensiveReviewAttempt) error {
			for i := range r.Candidates {
				c := &r.Candidates[i]
				if c.ID == id && c.Result == nil {
					now := time.Now().UTC()
					c.Status, c.LastError, c.StartedAt = "running", "", &now
					c.AttemptCount++
					// Checkpoint the invocation before calling the provider: a
					// cancellation must not erase a potentially billable call.
					a.ModelCalls++
					input = c.Candidate
					return nil
				}
			}
			return db.ErrOffensiveReviewConflict
		})
		if err != nil {
			return
		}
		candidateCtx, done := context.WithTimeout(batchCtx, rt.candidateTimeout)
		result, metrics, modelErr := rt.review(candidateCtx, job.provider, input, job.maxTokens)
		done()
		_, err = s.editOffensiveJob(job, func(r *db.OffensiveReview, a *db.OffensiveReviewAttempt) error {
			// The invocation was counted before dispatch. Validation/context
			// failures can return zero calls without contacting the provider.
			a.ModelCalls += metrics.ModelCalls - 1
			a.InputTokens += metrics.Usage.InputTokens
			a.OutputTokens += metrics.Usage.OutputTokens
			a.ModelElapsedMS += metrics.ModelElapsedMS
			for i := range r.Candidates {
				c := &r.Candidates[i]
				if c.ID == id && c.Result == nil {
					now := time.Now().UTC()
					c.FinishedAt = &now
					if modelErr != nil {
						c.Status = "error"
						c.LastError = offensiveReviewError(modelErr)
					} else {
						c.Status = result.Status
						c.Result = &result
						c.LastError = ""
					}
					return nil
				}
			}
			return db.ErrOffensiveReviewConflict
		})
		if err != nil {
			return
		}
		if modelErr != nil {
			stoppedError = modelErr
			break
		}
	}
	status, reason := "partial", "이번 묶음 검토를 종료했습니다. 남은 후보를 이어서 검토할 수 있습니다."
	if stoppedError != nil {
		reason = offensiveReviewError(stoppedError) + " 추가 모델 호출 없이 이번 묶음을 종료했습니다."
	}
	if batchCtx.Err() != nil {
		status, reason = "interrupted", "검토 실행이 중단되거나 제한시간에 도달했습니다. 완료된 판정은 보존됩니다."
	}
	s.finishOffensiveReview(job, status, reason)
}

func offensiveReviewError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "후보 검토 제한시간(최대 300초)에 도달했습니다. 이어하기로 이 후보를 다시 검토할 수 있습니다."
	}
	if errors.Is(err, context.Canceled) {
		return "검토가 중단되었습니다. 저장된 후보 판정은 유지됩니다."
	}
	for _, safe := range []error{offensivereview.ErrInvalidCandidate, offensivereview.ErrNoProvider, offensivereview.ErrModelCall, offensivereview.ErrRateLimited, offensivereview.ErrInvalidOutput, offensivereview.ErrTruncatedOutput, offensivereview.ErrToolsNotAllowed} {
		if errors.Is(err, safe) {
			return safe.Error()
		}
	}
	return "모델 호출 또는 근거 판정 형식 검증에 실패했습니다. LLM 연결 상태를 확인한 뒤 이어서 검토하세요."
}

func (s *Server) finishOffensiveReview(job *offensiveReviewJob, status, reason string) {
	_, _ = s.editOffensiveJob(job, func(r *db.OffensiveReview, a *db.OffensiveReviewAttempt) error {
		now := time.Now().UTC()
		r.RefreshCounts()
		if r.Pending == 0 {
			status, reason = "completed", "모든 후보의 근거 판정을 저장했습니다."
		}
		r.Status, r.Reason, r.Owner, r.LeaseUntil = status, reason, "", time.Time{}
		for i := range r.Candidates {
			if r.Candidates[i].Status == "running" {
				r.Candidates[i].Status = "pending"
			}
		}
		a.Status, a.Reason, a.FinishedAt = status, reason, &now
		var activeElapsed *time.Duration
		if !job.startedAt.IsZero() {
			elapsed := time.Since(job.startedAt)
			activeElapsed = &elapsed
		}
		a.RecordElapsed(now, activeElapsed)
		return nil
	})
}

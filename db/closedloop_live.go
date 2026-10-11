package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/google/uuid"
)

var ErrClosedLoopLiveConflict = errors.New("실행 또는 규칙 버전이 변경됐거나 현재 단계에서 허용되지 않는 작업입니다. 새로고침해 주세요")

type ClosedLoopLiveInput struct {
	RequestID    string                 `json:"request_id"`
	FindingID    int64                  `json:"finding_id,string"`
	Scenario     string                 `json:"scenario"`
	Defense      DefenseExecutionInput  `json:"defense"`
	BaselineRule closedloop.Rule        `json:"baseline_rule"`
	Notes        string                 `json:"notes"`
	LogTarget    string                 `json:"log_target"`
	LogPath      string                 `json:"log_path"`
	LogMapping   *investigation.Mapping `json:"log_mapping,omitempty"`
}
type ClosedLoopLiveCycle struct {
	ID              int64                        `json:"id,string"`
	FindingID       int64                        `json:"finding_id,string"`
	Scenario        string                       `json:"scenario"`
	Status          string                       `json:"status"`
	Revision        int64                        `json:"revision"`
	BaselineRule    closedloop.Rule              `json:"baseline_rule"`
	CandidateRule   *closedloop.Rule             `json:"candidate_rule"`
	Baseline        *DefenseExecution            `json:"baseline"`
	Current         *DefenseExecution            `json:"current"`
	LogTarget       string                       `json:"log_target"`
	LogPath         string                       `json:"log_path"`
	LogMapping      investigation.Mapping        `json:"log_mapping"`
	RemediationNote string                       `json:"remediation_note"`
	Observations    []*ClosedLoopLiveObservation `json:"observations"`
	Comparison      ClosedLoopLiveComparison     `json:"comparison"`
	CreatedAt       time.Time                    `json:"created_at"`
	UpdatedAt       time.Time                    `json:"updated_at"`
	requestID       string
	inputSHA        string
}
type ClosedLoopNativeRuleRef struct {
	DetectionRuleID string `json:"detection_rule_id"`
	RuleSHA256      string `json:"rule_sha256"`
}
type ClosedLoopLiveObservation struct {
	ID             int64                                  `json:"id,string"`
	Phase          string                                 `json:"phase"`
	ExecutionID    int64                                  `json:"execution_id,string"`
	AssessmentID   int64                                  `json:"assessment_id,string"`
	RuleRevision   int64                                  `json:"rule_revision"`
	Native         *DefenseAssessment                     `json:"native"`
	NativeRuleRefs []ClosedLoopNativeRuleRef              `json:"native_rule_refs"`
	Shadow         *securitysource.ClosedLoopSearchResult `json:"shadow"`
	EvidenceSHA256 string                                 `json:"evidence_sha256"`
	CreatedAt      time.Time                              `json:"created_at"`
}
type ClosedLoopLiveComparison struct {
	Comparable                   bool     `json:"comparable"`
	Reasons                      []string `json:"reasons"`
	BaselineNativeDetection      string   `json:"baseline_native_detection"`
	CurrentNativeDetection       string   `json:"current_native_detection"`
	BaselineShadowDetection      string   `json:"baseline_shadow_detection"`
	CandidateShadowDetection     string   `json:"candidate_shadow_detection"`
	CandidateNativeRuleDetection string   `json:"candidate_native_rule_detection"`
	Precision                    *float64 `json:"precision"`
	Recall                       *float64 `json:"recall"`
	FalsePositiveRate            *float64 `json:"false_positive_rate"`
	MTTDSeconds                  *float64 `json:"mttd_seconds"`
}
type ClosedLoopLiveSummary struct {
	ID        int64     `json:"id,string"`
	FindingID int64     `json:"finding_id,string"`
	Scenario  string    `json:"scenario"`
	Status    string    `json:"status"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type liveSettings struct {
	InputSHA   string                `json:"input_sha256"`
	LogTarget  string                `json:"log_target"`
	LogPath    string                `json:"log_path"`
	LogMapping investigation.Mapping `json:"log_mapping"`
}

const liveSelect = `SELECT id,request_id::text,finding_id,scenario,status,revision,baseline_rule,candidate_rule,payload,baseline_snapshot,current_snapshot,remediation_note,created_at,updated_at FROM closed_loop_live_cycles `

func scanLiveCycle(row interface{ Scan(...any) error }) (*ClosedLoopLiveCycle, error) {
	c := &ClosedLoopLiveCycle{Observations: []*ClosedLoopLiveObservation{}}
	var b, r, p, e, current []byte
	if err := row.Scan(&c.ID, &c.requestID, &c.FindingID, &c.Scenario, &c.Status, &c.Revision, &b, &r, &p, &e, &current, &c.RemediationNote, &c.CreatedAt, &c.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClosedLoopNotFound
		}
		return nil, err
	}
	var settings liveSettings
	for _, v := range []struct {
		raw []byte
		out any
	}{{b, &c.BaselineRule}, {p, &settings}, {e, &c.Baseline}} {
		if err := json.Unmarshal(v.raw, v.out); err != nil {
			return nil, err
		}
	}
	if len(r) > 0 {
		if err := json.Unmarshal(r, &c.CandidateRule); err != nil {
			return nil, err
		}
	}
	if len(current) > 0 {
		if err := json.Unmarshal(current, &c.Current); err != nil {
			return nil, err
		}
	}
	c.inputSHA, c.LogTarget, c.LogPath, c.LogMapping = settings.InputSHA, settings.LogTarget, settings.LogPath, settings.LogMapping
	return c, nil
}
func liveRuleValid(rule closedloop.Rule, m investigation.Mapping) error {
	if err := closedloop.ValidateRule(rule); err != nil {
		return err
	}
	if !utf8.ValidString(rule.Name) || strings.ContainsAny(rule.Name, "\x00\r\n") {
		return fmt.Errorf("%w: 규칙 이름을 확인하세요", closedloop.ErrInvalid)
	}
	allowed := map[string]bool{}
	for _, f := range securitysource.ClosedLoopRuleFields(m) {
		allowed[f] = true
	}
	for _, b := range rule.Any {
		for _, cond := range b.All {
			if !allowed[cond.Field] || !utf8.ValidString(cond.Value) || strings.ContainsAny(cond.Value, "\x00\r\n") {
				return fmt.Errorf("%w: 원본 감사 로그의 허용된 행동 필드만 규칙에 사용할 수 있습니다", closedloop.ErrInvalid)
			}
		}
	}
	return nil
}
func liveScope(e *DefenseExecution, target, path string, mapping *investigation.Mapping) (string, string, investigation.Mapping, error) {
	var snap struct {
		Assets []struct {
			URL, Domain, IP string
			Port            int
		}
	}
	if err := json.Unmarshal(e.DiagnosisSnapshot, &snap); err != nil {
		return "", "", investigation.Mapping{}, err
	}
	targets := map[string]bool{}
	var inferred string
	for _, a := range snap.Assets {
		values := []string{}
		if u, err := url.Parse(a.URL); err == nil && u.Host != "" {
			values = append(values, u.Host)
		}
		for _, host := range []string{a.Domain, a.IP} {
			if host == "" {
				continue
			}
			if a.Port > 0 {
				host = net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(a.Port))
			}
			values = append(values, host)
		}
		for _, v := range values {
			if v != "" {
				targets[strings.ToLower(v)] = true
				if inferred == "" {
					inferred = v
				}
			}
		}
	}
	if target == "" {
		target = inferred
	}
	if target == "" || !targets[strings.ToLower(target)] {
		return "", "", investigation.Mapping{}, fmt.Errorf("%w: 로그 대상은 원본 취약점의 허가된 자산과 같아야 합니다", closedloop.ErrInvalid)
	}
	if path == "" {
		path = "/"
	}
	now := time.Now().UTC()
	if err := investigation.ValidateScope(investigation.Scope{Target: target, PathPrefix: path, Start: now.Add(-time.Minute), End: now}, now); err != nil {
		return "", "", investigation.Mapping{}, fmt.Errorf("%w: %v", closedloop.ErrInvalid, err)
	}
	m := investigation.DefaultMapping()
	if mapping != nil {
		m = *mapping
	}
	var s struct {
		Config struct {
			CorrelationField string `json:"correlation_field"`
		}
	}
	if err := json.Unmarshal(e.SourceSnapshot, &s); err != nil {
		return "", "", m, err
	}
	m.VerificationID = s.Config.CorrelationField
	if err := investigation.ValidateMapping(m); err != nil {
		return "", "", m, fmt.Errorf("%w: %v", closedloop.ErrInvalid, err)
	}
	if m.Target == "" || m.Path == "" || m.VerificationID == "" {
		return "", "", m, fmt.Errorf("%w: 대상·경로·실행 ID 매핑이 필요합니다", closedloop.ErrInvalid)
	}
	return target, path, m, nil
}

// Cycle and its first real ARTEX conversation become durable in the same tx.
// Reusing a request key never creates or dispatches a second actual execution.
func (d *DB) CreateClosedLoopLiveCycle(ctx context.Context, in ClosedLoopLiveInput) (*ClosedLoopLiveCycle, *FindingRetest, *Conversation, *DefenseExecution, bool, error) {
	if _, err := uuid.Parse(in.RequestID); err != nil || in.FindingID <= 0 {
		return nil, nil, nil, nil, false, fmt.Errorf("%w: 요청 UUID와 취약점 ID가 필요합니다", closedloop.ErrInvalid)
	}
	var err error
	in.Scenario, err = defenseText(in.Scenario, "시나리오", 1, 200)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	in.Notes, err = defenseText(in.Notes, "추가 설명", 0, 4000)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	if in.Defense.BaselineID != nil {
		return nil, nil, nil, nil, false, fmt.Errorf("%w: 최초 실행에 이전 실행을 지정할 수 없습니다", closedloop.ErrInvalid)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	sha := closedloop.Hash(raw)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	defer tx.Rollback()
	if err = LockFindingEvidenceTx(tx, in.FindingID, nil); err != nil {
		return nil, nil, nil, nil, false, err
	}
	old, err := scanLiveCycle(tx.QueryRowContext(ctx, liveSelect+`WHERE request_id=$1 FOR UPDATE`, in.RequestID))
	if err == nil {
		if old.inputSHA != sha {
			return nil, nil, nil, nil, false, ErrClosedLoopLiveConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, nil, nil, nil, false, err
		}
		c, e := old, previewLiveExecution(old.Baseline)
		return previewLiveCycle(c), e.Retest, nil, e, false, nil
	}
	if !errors.Is(err, ErrClosedLoopNotFound) {
		return nil, nil, nil, nil, false, err
	}
	r, conv, e, created, err := createFindingRetestTx(ctx, tx, in.FindingID, in.Notes, &in.Defense)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	target, path, m, err := liveScope(e, in.LogTarget, in.LogPath, in.LogMapping)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	if err = liveRuleValid(in.BaselineRule, m); err != nil {
		return nil, nil, nil, nil, false, err
	}
	settings, _ := json.Marshal(liveSettings{sha, target, path, m})
	rule, _ := json.Marshal(in.BaselineRule)
	snapshot, _ := json.Marshal(e)
	c, err := scanLiveCycle(tx.QueryRowContext(ctx, `INSERT INTO closed_loop_live_cycles(request_id,finding_id,scenario,baseline_execution_id,status,baseline_rule,payload,baseline_snapshot) VALUES($1,$2,$3,$4,'baseline_running',$5,$6,$7) RETURNING id,request_id::text,finding_id,scenario,status,revision,baseline_rule,candidate_rule,payload,baseline_snapshot,current_snapshot,remediation_note,created_at,updated_at`, in.RequestID, in.FindingID, in.Scenario, e.ID, rule, settings, snapshot))
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, nil, nil, false, err
	}
	return previewLiveCycle(c), r, conv, previewLiveExecution(e), created, nil
}
func (d *DB) ListClosedLoopLiveCycles(ctx context.Context) ([]ClosedLoopLiveSummary, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,finding_id,scenario,status,revision,created_at,updated_at FROM closed_loop_live_cycles ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClosedLoopLiveSummary{}
	for rows.Next() {
		var c ClosedLoopLiveSummary
		if err := rows.Scan(&c.ID, &c.FindingID, &c.Scenario, &c.Status, &c.Revision, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (d *DB) GetClosedLoopLiveCycle(ctx context.Context, id int64, export bool) (*ClosedLoopLiveCycle, error) {
	c, err := scanLiveCycle(d.QueryRowContext(ctx, liveSelect+`WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	for _, dst := range []**DefenseExecution{&c.Baseline, &c.Current} {
		if *dst == nil {
			continue
		}
		fresh, err := d.GetDefenseExecutionForCollection(ctx, c.FindingID, (*dst).ID)
		if err == nil {
			*dst = fresh
		} else if errors.Is(err, ErrDefenseExecutionNotFound) {
			(*dst).State = "stale"
		} else {
			return nil, err
		}
	}
	column := "summary"
	if export {
		column = "payload"
	}
	rows, err := d.QueryContext(ctx, `SELECT id,`+column+`,created_at FROM closed_loop_live_observations WHERE cycle_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var o ClosedLoopLiveObservation
		var raw []byte
		if err := rows.Scan(&o.ID, &raw, &o.CreatedAt); err != nil {
			return nil, err
		}
		rowID, created := o.ID, o.CreatedAt
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		o.ID, o.CreatedAt = rowID, created
		c.Observations = append(c.Observations, &o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	active := c.Baseline
	if c.Current != nil {
		active = c.Current
	}
	if c.Status != "stopped" && active != nil && active.Retest != nil && (active.Retest.Status == "stopped" || active.Retest.Status == "failed") {
		c.Status = "inconclusive"
	}
	c.Comparison = compareLiveCycle(c)
	if !export {
		return previewLiveCycle(c), nil
	}
	return c, nil
}
func previewLiveExecution(e *DefenseExecution) *DefenseExecution {
	if e == nil {
		return nil
	}
	out := *e
	out.DiagnosisSnapshot = nil
	out.Assessments = []*DefenseAssessment{}
	if e.Retest != nil {
		r := *e.Retest
		r.Snapshot = nil
		r.Evidence = ""
		out.Retest = &r
	}
	return &out
}
func previewLiveObservation(o *ClosedLoopLiveObservation) *ClosedLoopLiveObservation {
	out := *o
	if o.Native != nil {
		n := *o.Native
		n.Evidence = nil
		out.Native = &n
	}
	if o.Shadow != nil {
		s := *o.Shadow
		s.Files = nil
		s.Events = append([]securitysource.ClosedLoopRuleEvent{}, s.Events...)
		for i := range s.Events {
			s.Events[i].Raw = nil
		}
		if s.Upload != nil {
			u := *s.Upload
			u.Files = append([]securitysource.UploadedFileEvidence{}, u.Files...)
			for i := range u.Files {
				u.Files[i].Content = ""
			}
			s.Upload = &u
		}
		out.Shadow = &s
	}
	return &out
}
func previewLiveCycle(c *ClosedLoopLiveCycle) *ClosedLoopLiveCycle {
	out := *c
	out.Baseline = previewLiveExecution(c.Baseline)
	out.Current = previewLiveExecution(c.Current)
	out.Observations = []*ClosedLoopLiveObservation{}
	for _, o := range c.Observations {
		out.Observations = append(out.Observations, previewLiveObservation(o))
	}
	out.Comparison = compareLiveCycle(&out)
	return &out
}
func shadowState(s *securitysource.ClosedLoopSearchResult, candidate bool) string {
	if s == nil || !s.Complete || s.Truncated > 0 || s.ErrorCode != "" || len(s.Events) == 0 {
		return "inconclusive"
	}
	hit := false
	for _, e := range s.Events {
		state := e.Baseline
		if candidate {
			state = e.Candidate
		}
		if state == "unknown" {
			return "inconclusive"
		}
		if state == "match" {
			hit = true
		} else if state != "no_match" {
			return "inconclusive"
		}
	}
	if hit {
		return "matched"
	}
	return "not_matched"
}
func compareLiveCycle(c *ClosedLoopLiveCycle) ClosedLoopLiveComparison {
	out := ClosedLoopLiveComparison{Reasons: []string{}, BaselineNativeDetection: "inconclusive", CurrentNativeDetection: "inconclusive", BaselineShadowDetection: "inconclusive", CandidateShadowDetection: "inconclusive", CandidateNativeRuleDetection: "not_attributed"}
	var b, r *ClosedLoopLiveObservation
	for _, o := range c.Observations {
		if o.Phase == "baseline" && b == nil {
			b = o
		}
		if o.Phase == "rerun" && r == nil && o.RuleRevision == c.Revision {
			r = o
		}
	}
	if b != nil && b.Native != nil {
		out.BaselineNativeDetection = b.Native.Detection
	}
	if r != nil && r.Native != nil {
		out.CurrentNativeDetection = r.Native.Detection
		out.BaselineShadowDetection = shadowState(r.Shadow, false)
		out.CandidateShadowDetection = shadowState(r.Shadow, true)
		if c.Current != nil && c.Current.SourceKind == "splunk" && r.Native.Detection == "detected" && r.Shadow != nil {
			for _, ref := range r.NativeRuleRefs {
				if ref.DetectionRuleID != "" && ref.RuleSHA256 == r.Shadow.CandidateRuleSHA256 {
					out.CandidateNativeRuleDetection = "detected"
					break
				}
			}
		}
	}
	if b == nil || r == nil || c.Current == nil {
		out.Reasons = append(out.Reasons, "첫 실행과 새 재실행의 수집 근거가 모두 필요합니다")
		return out
	}
	if c.Status == "stopped" || c.Baseline.State != "current" || c.Current.State != "current" {
		out.Reasons = append(out.Reasons, "실행이 중지됐거나 원본·연결 설정이 변경됐습니다")
	}
	if c.Baseline.CorrelationID == c.Current.CorrelationID || c.Baseline.ID == c.Current.ID || c.Baseline.Retest == nil || c.Current.Retest == nil || c.Baseline.Retest.FinishedAt == nil || !c.Current.CreatedAt.After(*c.Baseline.Retest.FinishedAt) {
		out.Reasons = append(out.Reasons, "새 실행 ID와 기준 실행 이후의 독립 실행 시각이 확인되지 않았습니다")
	}
	for _, e := range []*DefenseExecution{c.Baseline, c.Current} {
		if e.Retest == nil || e.Retest.Status != "completed" || e.Retest.Error != "" {
			out.Reasons = append(out.Reasons, "ARTEX 실행이 정상 완료되지 않았습니다")
			break
		}
	}
	if b.Native == nil || r.Native == nil || b.Native.Detection == "inconclusive" || r.Native.Detection == "inconclusive" || shadowState(b.Shadow, false) == "inconclusive" || out.BaselineShadowDetection == "inconclusive" || out.CandidateShadowDetection == "inconclusive" {
		out.Reasons = append(out.Reasons, "수집 범위 또는 탐지 판정 근거가 불완전합니다")
	}
	out.Comparable = len(out.Reasons) == 0
	out.Reasons = append(out.Reasons, "새 재실행의 같은 감사 로그에 두 규칙을 시험 평가합니다. 실제 경보 발생과 규칙 매칭은 별도 결과입니다", "경보 탐지 결과는 기존 모든 원격 탐지기의 결과이며, 후보 규칙 SHA가 일치하는 명시적 경보만 후보의 실제 탐지 근거로 구분합니다", "정상 트래픽의 정답 데이터와 독립 경보 시각이 없어 정확도·오탐률·MTTD는 산출하지 않습니다")
	if c.Baseline.SourceKind == "file" {
		out.Reasons = append(out.Reasons, "파일 평가는 업로더 출처·수집 범위 확인에 의존하며 Splunk 원격 규칙 실행이 아닙니다")
	}
	return out
}
func (d *DB) GetLatestClosedLoopNativeAssessment(ctx context.Context, findingID, executionID int64) (*DefenseAssessment, error) {
	a, err := scanDefenseAssessment(d.QueryRowContext(ctx, `SELECT id,execution_id,detection,prevention,reasons,recommendations,diagnostics,evidence,created_at FROM finding_defense_assessments WHERE finding_id=$1 AND execution_id=$2 ORDER BY id DESC LIMIT 1`, findingID, executionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClosedLoopLiveConflict
	}
	return a, err
}
func lockLiveCycle(ctx context.Context, tx *sql.Tx, id int64) (*ClosedLoopLiveCycle, error) {
	var fid int64
	if err := tx.QueryRowContext(ctx, `SELECT finding_id FROM closed_loop_live_cycles WHERE id=$1`, id).Scan(&fid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClosedLoopNotFound
		}
		return nil, err
	}
	if err := LockFindingEvidenceTx(tx, fid, nil); err != nil {
		return nil, err
	}
	return scanLiveCycle(tx.QueryRowContext(ctx, liveSelect+`WHERE id=$1 FOR UPDATE`, id))
}
func (d *DB) SetClosedLoopLiveCandidate(ctx context.Context, id, revision int64, rule closedloop.Rule, note string) (*ClosedLoopLiveCycle, error) {
	note, err := defenseText(note, "개선 설명", 1, 8000)
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := lockLiveCycle(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if c.Revision != revision || c.Current != nil || c.Status == "stopped" {
		return nil, ErrClosedLoopLiveConflict
	}
	var observed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM closed_loop_live_observations WHERE cycle_id=$1 AND phase='baseline' AND (summary#>>'{native,audit_count}')::int>0)`, id).Scan(&observed); err != nil {
		return nil, err
	}
	if !observed {
		return nil, ErrClosedLoopLiveConflict
	}
	if err = liveRuleValid(rule, c.LogMapping); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(rule)
	_, err = tx.ExecContext(ctx, `UPDATE closed_loop_live_cycles SET candidate_rule=$2,revision=revision+1,remediation_note=$3,status='candidate_ready',updated_at=clock_timestamp() WHERE id=$1`, id, raw, note)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetClosedLoopLiveCycle(ctx, id, false)
}
func (d *DB) RerunClosedLoopLiveCycle(ctx context.Context, id, revision int64) (*ClosedLoopLiveCycle, *FindingRetest, *Conversation, *DefenseExecution, bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	defer tx.Rollback()
	c, err := lockLiveCycle(ctx, tx, id)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	if c.Revision != revision || c.Status == "stopped" || c.CandidateRule == nil {
		return nil, nil, nil, nil, false, ErrClosedLoopLiveConflict
	}
	if c.Current != nil {
		if err = tx.Commit(); err != nil {
			return nil, nil, nil, nil, false, err
		}
		out, err := d.GetClosedLoopLiveCycle(ctx, id, false)
		if err != nil {
			return nil, nil, nil, nil, false, err
		}
		return out, out.Current.Retest, nil, out.Current, false, nil
	}
	b, err := getDefenseExecutionMetadataTx(ctx, tx, c.FindingID, c.Baseline.ID)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	if b.State != "current" || b.Retest == nil || b.Retest.Status != "completed" || b.Retest.FinishedAt == nil || b.Retest.Error != "" {
		return nil, nil, nil, nil, false, ErrClosedLoopLiveConflict
	}
	var observed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM closed_loop_live_observations WHERE cycle_id=$1 AND phase='baseline' AND (summary#>>'{native,audit_count}')::int>0)`, id).Scan(&observed); err != nil {
		return nil, nil, nil, nil, false, err
	}
	if !observed {
		return nil, nil, nil, nil, false, ErrClosedLoopLiveConflict
	}
	in := DefenseExecutionInput{SourceKind: b.SourceKind, SourceID: b.SourceID, PlanRevision: b.PlanSnapshot.Revision, ExpectedEvidenceVersion: &b.EvidenceVersion, ExpectedSourceFingerprint: b.SourceFingerprint, BaselineID: &b.ID, RemediationNote: c.RemediationNote}
	if b.SourceKind == "file" {
		cfg, err := defenseExecutionFileConfig(b)
		if err != nil {
			return nil, nil, nil, nil, false, err
		}
		in.FileConfig = &cfg
	}
	r, conv, e, created, err := createFindingRetestTx(ctx, tx, c.FindingID, "Closed-loop 재실행: 원본 조건을 유지하고 새 실행 ID로 실제 재검증합니다. 규칙 개선은 별도 로그 판정으로 검증합니다.", &in)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	if e.CorrelationID == b.CorrelationID || !e.CreatedAt.After(*b.Retest.FinishedAt) {
		return nil, nil, nil, nil, false, ErrClosedLoopLiveConflict
	}
	snapshot, _ := json.Marshal(e)
	base, _ := json.Marshal(b)
	_, err = tx.ExecContext(ctx, `UPDATE closed_loop_live_cycles SET current_execution_id=$2,current_snapshot=$3,baseline_snapshot=$4,status='rerun_running',updated_at=clock_timestamp() WHERE id=$1`, id, e.ID, snapshot, base)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, nil, nil, false, err
	}
	out, err := d.GetClosedLoopLiveCycle(ctx, id, false)
	return out, r, conv, previewLiveExecution(e), created, err
}

// Accept a single distinct scalar, including duplicate values emitted by
// automatic extraction plus spath. Conflicting values never prove attribution.
func liveScalar(raw json.RawMessage) (string, bool) {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value, true
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return "", false
	}
	value = values[0]
	for _, v := range values {
		if v != value {
			return "", false
		}
	}
	return value, true
}
func liveRawFields(raw json.RawMessage) map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	if inner, ok := liveScalar(fields["_raw"]); ok {
		var nested map[string]json.RawMessage
		if json.Unmarshal([]byte(inner), &nested) == nil {
			for k, v := range nested {
				if previous, exists := fields[k]; !exists {
					fields[k] = v
				} else {
					a, aok := liveScalar(previous)
					b, bok := liveScalar(v)
					if aok && bok && a != b {
						fields[k] = json.RawMessage(`null`)
					}
				}
			}
		}
	}
	return fields
}
func nativeRuleRefs(e *securitysource.Evidence) []ClosedLoopNativeRuleRef {
	out := []ClosedLoopNativeRuleRef{}
	seen := map[string]bool{}
	if e == nil {
		return out
	}
	for _, event := range e.Events {
		if event.Kind != "alert" {
			continue
		}
		fields := liveRawFields(event.Raw)
		id, ok := liveScalar(fields["detection_rule_id"])
		if !ok || id == "" || len(id) > 200 || strings.ContainsAny(id, "\x00\r\n") {
			continue
		}
		sha, ok := liveScalar(fields["rule_sha256"])
		if !ok || len(sha) != 64 || sha != strings.ToLower(sha) {
			continue
		}
		if _, err := hex.DecodeString(sha); err != nil {
			continue
		}
		key := id + "|" + sha
		if !seen[key] {
			seen[key] = true
			out = append(out, ClosedLoopNativeRuleRef{id, sha})
		}
	}
	return out
}

// Only server-fetched or server-validated uploaded assessments reach this method.
// The database independently binds them to an immutable phase/revision/window.
func (d *DB) SaveClosedLoopLiveObservation(ctx context.Context, id, executionID, revision int64, native *DefenseAssessment, shadow *securitysource.ClosedLoopSearchResult) (*ClosedLoopLiveCycle, error) {
	if native == nil || native.Evidence == nil || shadow == nil || native.ExecutionID != executionID {
		return nil, ErrClosedLoopLiveConflict
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := lockLiveCycle(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	phase := "baseline"
	e := c.Baseline
	candidate := c.BaselineRule
	rev := int64(1)
	if c.Current != nil {
		phase = "rerun"
		e = c.Current
		candidate = *c.CandidateRule
		rev = c.Revision
	}
	if c.Status == "stopped" || e.ID != executionID || revision != c.Revision {
		return nil, ErrClosedLoopLiveConflict
	}
	current, err := getDefenseExecutionMetadataTx(ctx, tx, c.FindingID, e.ID)
	if err != nil {
		return nil, err
	}
	if current.State != "current" || current.Retest == nil || current.Retest.FinishedAt == nil {
		return nil, ErrClosedLoopLiveConflict
	}
	b, _ := json.Marshal(c.BaselineRule)
	cr, _ := json.Marshal(candidate)
	if shadow.CorrelationID != current.CorrelationID || shadow.BaselineRuleSHA256 != closedloop.Hash(b) || shadow.CandidateRuleSHA256 != closedloop.Hash(cr) || !shadow.WindowStart.Equal(native.Evidence.WindowStart) || !shadow.WindowEnd.Equal(native.Evidence.WindowEnd) {
		return nil, ErrClosedLoopLiveConflict
	}
	var stored bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM finding_defense_assessments WHERE id=$1 AND execution_id=$2 AND finding_id=$3)`, native.ID, executionID, c.FindingID).Scan(&stored); err != nil {
		return nil, err
	}
	if !stored {
		return nil, ErrClosedLoopLiveConflict
	}
	// Read persisted independent verdicts and original bytes. Internal DTO edits
	// cannot rewrite a source assessment when attaching it to a live cycle.
	native, err = scanDefenseAssessment(tx.QueryRowContext(ctx, `SELECT id,execution_id,detection,prevention,reasons,recommendations,diagnostics,evidence,created_at FROM finding_defense_assessments WHERE id=$1 AND execution_id=$2`, native.ID, executionID))
	if err != nil {
		return nil, err
	}
	if native.Evidence == nil || !shadow.WindowStart.Equal(native.Evidence.WindowStart) || !shadow.WindowEnd.Equal(native.Evidence.WindowEnd) {
		return nil, ErrClosedLoopLiveConflict
	}
	// Hash source bytes/events and rule/window identity, not mutable collection time.
	proof, _ := json.Marshal(struct {
		Execution      int64
		Revision       int64
		Native         []securitysource.Event
		Complete       bool
		Start, End     time.Time
		Shadow         []securitysource.ClosedLoopRuleEvent
		Files          []investigation.FileEvidence
		Rule           string
		ShadowComplete bool
		ShadowError    string
		ShadowWarnings []string
	}{executionID, rev, native.Evidence.Events, native.Evidence.Complete, native.Evidence.WindowStart, native.Evidence.WindowEnd, shadow.Events, shadow.Files, shadow.CandidateRuleSHA256, shadow.Complete, shadow.ErrorCode, shadow.Warnings})
	o := &ClosedLoopLiveObservation{Phase: phase, ExecutionID: executionID, AssessmentID: native.ID, RuleRevision: rev, Native: native, NativeRuleRefs: nativeRuleRefs(native.Evidence), Shadow: shadow, EvidenceSHA256: closedloop.Hash(proof)}
	payload, _ := json.Marshal(o)
	summary, _ := json.Marshal(previewLiveObservation(o))
	_, err = tx.ExecContext(ctx, `INSERT INTO closed_loop_live_observations(cycle_id,phase,execution_id,assessment_id,rule_revision,evidence_sha256,summary,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(cycle_id,phase,rule_revision,evidence_sha256) DO NOTHING`, id, phase, executionID, native.ID, rev, o.EvidenceSHA256, summary, payload)
	if err != nil {
		return nil, err
	}
	status := "inconclusive"
	if current.Retest.Status == "completed" && current.Retest.Error == "" && native.Detection != "inconclusive" && shadowState(shadow, false) != "inconclusive" && shadowState(shadow, true) != "inconclusive" {
		if phase == "baseline" {
			status = "baseline_ready"
			if c.CandidateRule != nil {
				status = "candidate_ready"
			}
		} else {
			status = "completed"
		}
	}
	snapshot, _ := json.Marshal(current)
	column := "baseline_snapshot"
	if phase == "rerun" {
		column = "current_snapshot"
	}
	_, err = tx.ExecContext(ctx, `UPDATE closed_loop_live_cycles SET status=$2,`+column+`=$3,updated_at=clock_timestamp() WHERE id=$1`, id, status, snapshot)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetClosedLoopLiveCycle(ctx, id, false)
}

type ClosedLoopLiveSuggestion struct {
	CandidateRule closedloop.Rule `json:"candidate_rule"`
	Warnings      []string        `json:"warnings"`
	AuditEventIDs []string        `json:"audit_event_ids"`
}

func (d *DB) SuggestClosedLoopLiveCandidate(ctx context.Context, id int64) (*ClosedLoopLiveSuggestion, error) {
	c, err := d.GetClosedLoopLiveCycle(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if c.Status == "stopped" || c.Current != nil {
		return nil, ErrClosedLoopLiveConflict
	}
	var raw []byte
	if err = d.QueryRowContext(ctx, `SELECT payload FROM closed_loop_live_observations WHERE cycle_id=$1 AND phase='baseline' ORDER BY id DESC LIMIT 1`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClosedLoopLiveConflict
		}
		return nil, err
	}
	var o ClosedLoopLiveObservation
	if err = json.Unmarshal(raw, &o); err != nil {
		return nil, err
	}
	if o.Native == nil || o.Native.Evidence == nil {
		return nil, ErrClosedLoopLiveConflict
	}
	out := &ClosedLoopLiveSuggestion{CandidateRule: closedloop.Rule{Name: "기준 감사 로그 후보", Any: []closedloop.Branch{}}, Warnings: []string{"기준 실행의 실제 감사 로그만 사용한 초안입니다. 재실행과 정상 트래픽 검증 전에는 운영 배포 또는 오탐률 개선을 주장할 수 없습니다"}, AuditEventIDs: []string{}}
	// Prefer the triggering request path plus method over IDs, IP memorization or labels.
	allowed := map[string]bool{}
	for _, f := range securitysource.ClosedLoopRuleFields(c.LogMapping) {
		allowed[f] = true
	}
	seen := map[string]bool{}
	if o.Shadow == nil || o.Native.AuditCount == 0 {
		return nil, ErrClosedLoopLiveConflict
	}
	if !o.Native.Evidence.Complete || !o.Shadow.Complete {
		out.Warnings = append(out.Warnings, "기준 로그 수집이 불완전합니다. 이 후보는 일부 실제 감사 이벤트에만 근거합니다")
	}
	// These rows are the adapter's original audit rows already checked against
	// the immutable target/path/UUID/window; unrelated native audits are excluded.
	for _, event := range o.Shadow.Events {
		fields := liveRawFields(event.Raw)
		var conditions []closedloop.Condition
		for _, f := range []string{c.LogMapping.Path, "request_target", "query_string", "method"} {
			if !allowed[f] {
				continue
			}
			var value string
			if json.Unmarshal(fields[f], &value) != nil || value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
				continue
			}
			if f == "query_string" && value == "" {
				continue
			}
			conditions = append(conditions, closedloop.Condition{Field: f, Op: "equals", Value: value, CaseSensitive: true})
			if len(conditions) == 2 {
				break
			}
		}
		if len(conditions) == 0 {
			continue
		}
		branch := closedloop.Branch{All: conditions}
		b, _ := json.Marshal(branch)
		key := string(b)
		if seen[key] {
			continue
		}
		seen[key] = true
		out.CandidateRule.Any = append(out.CandidateRule.Any, branch)
		out.AuditEventIDs = append(out.AuditEventIDs, event.EventID)
		if len(out.CandidateRule.Any) >= 8 {
			break
		}
	}
	if len(out.CandidateRule.Any) == 0 {
		return nil, fmt.Errorf("%w: 감사 로그에 후보 규칙을 만들 행동 필드가 없습니다. 필드 매핑을 확인하세요", closedloop.ErrInvalid)
	}
	if err := liveRuleValid(out.CandidateRule, c.LogMapping); err != nil {
		return nil, err
	}
	sort.Strings(out.AuditEventIDs)
	return out, nil
}
func (d *DB) StopClosedLoopLiveCycle(ctx context.Context, id int64) (*ClosedLoopLiveCycle, *int64, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	c, err := lockLiveCycle(ctx, tx, id)
	if err != nil {
		return nil, nil, err
	}
	e := c.Baseline
	if c.Current != nil {
		e = c.Current
	}
	var conv *int64
	if e != nil {
		r, err := scanRetest(tx.QueryRowContext(ctx, `UPDATE finding_retests SET status='stopped',finished_at=clock_timestamp(),error='사용자가 Closed-loop 실행을 중지했습니다' WHERE id=$1 AND status IN ('pending','running') RETURNING `+retestCols, e.RetestID))
		if err != nil {
			return nil, nil, err
		}
		if r != nil {
			conv = r.ConversationID
			if err = snapshotDefenseRetestTx(ctx, tx, r.ID); err != nil {
				return nil, nil, err
			}
		}
		// Preserve terminal status even if the linked original finding is deleted.
		if current, loadErr := getDefenseExecutionMetadataTx(ctx, tx, c.FindingID, e.ID); loadErr == nil {
			column := "baseline_snapshot"
			if c.Current != nil {
				column = "current_snapshot"
			}
			snapshot, _ := json.Marshal(current)
			if _, err = tx.ExecContext(ctx, `UPDATE closed_loop_live_cycles SET `+column+`=$2 WHERE id=$1`, id, snapshot); err != nil {
				return nil, nil, err
			}
		} else {
			return nil, nil, loadErr
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE closed_loop_live_cycles SET status='stopped',updated_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		return nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, err
	}
	out, err := d.GetClosedLoopLiveCycle(ctx, id, false)
	return out, conv, err
}

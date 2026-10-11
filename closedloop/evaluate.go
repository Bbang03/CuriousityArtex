// Package closedloop evaluates small transparent rules against separately
// labeled tuning and held-out datasets. It never executes an attack, runs a SIEM
// rule, deploys a change, or treats offline replay as live defensive validation.
package closedloop

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const EngineVersion = "aegis-exact-contains-v1"
const MaxCombinedBytes = 2 << 20
const MaxEvents = 1000
const MaxBranches = 24
const MaxConditions = 12

var ErrInvalid = errors.New("Closed-loop 입력이 올바르지 않습니다")

// Only fields are searchable; labels and event identities never enter matching.
type Event struct {
	EventID          string                     `json:"event_id"`
	Label            string                     `json:"label"`
	Fields           map[string]json.RawMessage `json:"fields"`
	OccurredAt       string                     `json:"occurred_at,omitempty"`
	BaselineAlertAt  string                     `json:"baseline_alert_at,omitempty"`
	CandidateAlertAt string                     `json:"candidate_alert_at,omitempty"`
}
type Condition struct {
	Field         string `json:"field"`
	Op            string `json:"op"`
	Value         string `json:"value"`
	CaseSensitive bool   `json:"case_sensitive"`
}
type Branch struct {
	All []Condition `json:"all"`
}
type Rule struct {
	Name string   `json:"name"`
	Any  []Branch `json:"any"`
}
type Input struct {
	Scenario                     string `json:"scenario"`
	FindingID                    int64  `json:"finding_id,string,omitempty"`
	CaseID                       int64  `json:"case_id,string,omitempty"`
	BaselineRule                 Rule   `json:"baseline_rule"`
	CandidateRule                Rule   `json:"candidate_rule"`
	TuningLogs                   string `json:"tuning_logs"`
	EvaluationLogs               string `json:"evaluation_logs"`
	Notes                        string `json:"notes"`
	TimestampProvenanceConfirmed bool   `json:"timestamp_provenance_confirmed"`
}
type Provenance struct {
	SHA256  string `json:"sha256"`
	Events  int    `json:"events"`
	Attacks int    `json:"attacks"`
	Benign  int    `json:"benign"`
}
type Dataset struct {
	Events     []Event
	Provenance Provenance
}
type Counts struct {
	TP            int `json:"tp"`
	FP            int `json:"fp"`
	TN            int `json:"tn"`
	FN            int `json:"fn"`
	UnknownAttack int `json:"unknown_attack"`
	UnknownBenign int `json:"unknown_benign"`
}
type Metrics struct {
	Counts
	Precision         *float64 `json:"precision"`
	Recall            *float64 `json:"recall"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
	Accuracy          *float64 `json:"accuracy"`
	MTTDSeconds       *float64 `json:"mttd_seconds"`
	TimedDetections   int      `json:"timed_detections"`
}
type Evidence struct {
	EventID       string   `json:"event_id"`
	Label         string   `json:"label"`
	Baseline      string   `json:"baseline"`
	Candidate     string   `json:"candidate"`
	MissingFields []string `json:"missing_fields"`
}
type Comparison struct {
	Baseline  Metrics `json:"baseline"`
	Candidate Metrics `json:"candidate"`
}
type Result struct {
	Engine                   string     `json:"engine"`
	Scope                    string     `json:"scope"`
	Tuning                   Provenance `json:"tuning"`
	Evaluation               Provenance `json:"evaluation"`
	BaselineRuleSHA256       string     `json:"baseline_rule_sha256"`
	CandidateRuleSHA256      string     `json:"candidate_rule_sha256"`
	TuningComparison         Comparison `json:"tuning_comparison"`
	EvaluationComparison     Comparison `json:"evaluation_comparison"`
	Evidence                 []Evidence `json:"evidence"`
	NextValidationPriorities []Priority `json:"next_validation_priorities"`
	Warnings                 []string   `json:"warnings"`
}
type Priority struct {
	Kind     string   `json:"kind"`
	EventIDs []string `json:"event_ids"`
}
type Suggestion struct {
	CandidateRule      Rule        `json:"candidate_rule"`
	Tuning             Provenance  `json:"tuning"`
	AddedConditions    []Condition `json:"added_conditions"`
	UnresolvedEventIDs []string    `json:"unresolved_event_ids"`
	Warnings           []string    `json:"warnings"`
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
func Hash(raw []byte) string    { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func ruleHash(rule Rule) string { raw, _ := json.Marshal(rule); return Hash(raw) }
func scalar(raw json.RawMessage) (string, bool) {
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return "", false
	}
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}
func strictDecode(raw []byte, target any) error {
	if err := uniqueJSONKeys(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

// Reject duplicate keys so conflicting labels/IDs cannot be silently overridden.
func uniqueJSONKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return errors.New("JSON nesting limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || keys[key] {
					return errors.New("duplicate JSON key")
				}
				keys[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	return walk(0)
}
func reservedField(field string) bool {
	switch strings.ToLower(field) {
	case "label", "event_id", "ground_truth", "occurred_at", "baseline_alert_at", "candidate_alert_at":
		return true
	}
	return false
}

func validateTimestamp(value string) bool {
	if value == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !t.IsZero()
}

func ParseDataset(raw string) (*Dataset, error) {
	if !utf8.ValidString(raw) || len(raw) == 0 || len(raw) > MaxCombinedBytes {
		return nil, invalid("로그는 비어 있지 않은 UTF-8 JSONL이며 2 MiB 이하여야 합니다")
	}
	out := &Dataset{Events: []Event{}, Provenance: Provenance{SHA256: Hash([]byte(raw))}}
	ids, contents := map[string]bool{}, map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	line := 0
	for scanner.Scan() {
		line++
		b := bytes.TrimSpace(scanner.Bytes())
		if line == 1 {
			b = bytes.TrimSpace(bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf}))
		}
		if len(b) == 0 {
			continue
		}
		if len(out.Events) >= MaxEvents {
			return nil, invalid("각 데이터셋은 최대 %d개 이벤트입니다", MaxEvents)
		}
		var e Event
		if err := strictDecode(b, &e); err != nil {
			return nil, invalid("%d행 JSON 또는 필드를 확인하세요", line)
		}
		if e.EventID == "" || len(e.EventID) > 128 || strings.TrimSpace(e.EventID) != e.EventID {
			return nil, invalid("%d행 event_id는 공백 없는 1~128바이트 식별자여야 합니다", line)
		}
		if ids[e.EventID] {
			return nil, invalid("중복 event_id: %s", e.EventID)
		}
		ids[e.EventID] = true
		if e.Label != "attack" && e.Label != "benign" {
			return nil, invalid("%d행 label은 attack 또는 benign이어야 합니다", line)
		}
		if len(e.Fields) == 0 || len(e.Fields) > 64 {
			return nil, invalid("%d행 fields는 1~64개 스칼라 필드여야 합니다", line)
		}
		for field, value := range e.Fields {
			if len(field) == 0 || len(field) > 128 || strings.TrimSpace(field) != field || reservedField(field) {
				return nil, invalid("%d행 필드 이름을 확인하세요", line)
			}
			text, ok := scalar(value)
			if !ok || len(text) > 4096 {
				return nil, invalid("%d행 %s 값은 4096바이트 이하 문자열·수·불리언이어야 합니다", line, field)
			}
		}
		if !validateTimestamp(e.OccurredAt) || !validateTimestamp(e.BaselineAlertAt) || !validateTimestamp(e.CandidateAlertAt) {
			return nil, invalid("%d행 시간은 RFC3339 형식이어야 합니다", line)
		}
		for _, at := range []string{e.BaselineAlertAt, e.CandidateAlertAt} {
			if at != "" {
				if e.OccurredAt == "" {
					return nil, invalid("%d행 경보 시간에는 occurred_at이 필요합니다", line)
				}
				start, _ := time.Parse(time.RFC3339Nano, e.OccurredAt)
				end, _ := time.Parse(time.RFC3339Nano, at)
				if end.Before(start) {
					return nil, invalid("%d행 경보 시간은 공격 시간 이전일 수 없습니다", line)
				}
			}
		}
		key := contentHash(e)
		if contents[key] {
			return nil, invalid("%d행은 동일 fields 내용을 가진 중복 이벤트입니다", line)
		}
		contents[key] = true
		out.Events = append(out.Events, e)
		if e.Label == "attack" {
			out.Provenance.Attacks++
		} else {
			out.Provenance.Benign++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, invalid("JSONL의 한 행은 64 KiB 이하여야 합니다")
	}
	if len(out.Events) == 0 {
		return nil, invalid("로그에 이벤트가 없습니다")
	}
	out.Provenance.Events = len(out.Events)
	return out, nil
}

// Canonical searchable scalar values ignore IDs, labels and observation times.
// Relabeling/reidentifying the same log cannot turn tuning data into held-out data.
func contentHash(e Event) string {
	normalized := map[string]string{}
	for key, raw := range e.Fields {
		normalized[key], _ = scalar(raw)
	}
	b, _ := json.Marshal(normalized)
	return Hash(b)
}
func ValidateRule(rule Rule) error {
	if len(rule.Name) == 0 || utf8.RuneCountInString(rule.Name) > 120 {
		return invalid("규칙 이름은 1~120자여야 합니다")
	}
	if len(rule.Any) == 0 || len(rule.Any) > MaxBranches {
		return invalid("규칙 any는 1~%d개 분기여야 합니다", MaxBranches)
	}
	for _, branch := range rule.Any {
		if len(branch.All) == 0 || len(branch.All) > MaxConditions {
			return invalid("all은 1~%d개 조건이어야 합니다", MaxConditions)
		}
		for _, c := range branch.All {
			if c.Field == "" || len(c.Field) > 128 || strings.TrimSpace(c.Field) != c.Field || reservedField(c.Field) {
				return invalid("규칙은 fields 내부의 유효한 필드만 참조할 수 있습니다")
			}
			if c.Op != "equals" && c.Op != "contains" {
				return invalid("지원 연산자는 equals와 contains입니다")
			}
			if c.Value == "" || len(c.Value) > 1024 {
				return invalid("조건 값은 1~1024바이트여야 합니다")
			}
		}
	}
	return nil
}
func match(e Event, rule Rule) (string, []string) {
	unknown := false
	missing := map[string]bool{}
	for _, branch := range rule.Any {
		branchUnknown, branchFalse := false, false
		for _, c := range branch.All {
			raw, ok := e.Fields[c.Field]
			if !ok {
				branchUnknown = true
				missing[c.Field] = true
				continue
			}
			value, _ := scalar(raw)
			expected := c.Value
			if !c.CaseSensitive {
				value = strings.ToLower(value)
				expected = strings.ToLower(expected)
			}
			hit := value == expected
			if c.Op == "contains" {
				hit = strings.Contains(value, expected)
			}
			if !hit {
				branchFalse = true
			}
		}
		if !branchFalse && !branchUnknown {
			return "match", []string{}
		}
		if !branchFalse && branchUnknown {
			unknown = true
		}
	}
	list := make([]string, 0, len(missing))
	for field := range missing {
		list = append(list, field)
	}
	sort.Strings(list)
	if unknown {
		return "unknown", list
	}
	return "no_match", []string{}
}
func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	value := float64(n) / float64(d)
	return &value
}
func summarize(events []Event, rule Rule, kind string, timestampsConfirmed bool) Metrics {
	out := Metrics{}
	totalDelay := float64(0)
	for _, e := range events {
		state, _ := match(e, rule)
		if e.Label == "attack" {
			switch state {
			case "match":
				out.TP++
			case "no_match":
				out.FN++
			default:
				out.UnknownAttack++
			}
		} else {
			switch state {
			case "match":
				out.FP++
			case "no_match":
				out.TN++
			default:
				out.UnknownBenign++
			}
		}
		if timestampsConfirmed && e.Label == "attack" && state == "match" {
			at := e.BaselineAlertAt
			if kind == "candidate" {
				at = e.CandidateAlertAt
			}
			if e.OccurredAt != "" && at != "" {
				start, _ := time.Parse(time.RFC3339Nano, e.OccurredAt)
				end, _ := time.Parse(time.RFC3339Nano, at)
				totalDelay += end.Sub(start).Seconds()
				out.TimedDetections++
			}
		}
	}
	out.Precision = ratio(out.TP, out.TP+out.FP)
	if out.UnknownAttack == 0 {
		out.Recall = ratio(out.TP, out.TP+out.FN)
	}
	if out.UnknownBenign == 0 {
		out.FalsePositiveRate = ratio(out.FP, out.FP+out.TN)
	}
	if out.UnknownAttack+out.UnknownBenign == 0 {
		out.Accuracy = ratio(out.TP+out.TN, len(events))
	}
	// Partial timestamp samples must not masquerade as a full MTTD estimate.
	if timestampsConfirmed && out.TP > 0 && out.TimedDetections == out.TP {
		value := totalDelay / float64(out.TP)
		out.MTTDSeconds = &value
	}
	return out
}
func compare(events []Event, baseline, candidate Rule, confirmed bool) Comparison {
	return Comparison{Baseline: summarize(events, baseline, "baseline", confirmed), Candidate: summarize(events, candidate, "candidate", confirmed)}
}
func Evaluate(in Input) (*Result, error) {
	if strings.TrimSpace(in.Scenario) == "" || utf8.RuneCountInString(in.Scenario) > 200 || utf8.RuneCountInString(in.Notes) > 4000 || in.FindingID < 0 || in.CaseID < 0 {
		return nil, invalid("시나리오(1~200자), 메모(4000자 이하), 연결 ID를 확인하세요")
	}
	if len(in.TuningLogs)+len(in.EvaluationLogs) > MaxCombinedBytes {
		return nil, invalid("두 데이터셋 합계는 2 MiB 이하여야 합니다")
	}
	if err := ValidateRule(in.BaselineRule); err != nil {
		return nil, err
	}
	if err := ValidateRule(in.CandidateRule); err != nil {
		return nil, err
	}
	tuning, err := ParseDataset(in.TuningLogs)
	if err != nil {
		return nil, err
	}
	evaluation, err := ParseDataset(in.EvaluationLogs)
	if err != nil {
		return nil, err
	}
	ids, contents := map[string]bool{}, map[string]bool{}
	for _, event := range tuning.Events {
		ids[event.EventID] = true
		contents[contentHash(event)] = true
	}
	for _, event := range evaluation.Events {
		if ids[event.EventID] || contents[contentHash(event)] {
			return nil, invalid("개선용과 평가용 데이터가 겹칩니다: %s", event.EventID)
		}
	}
	out := &Result{Engine: EngineVersion, Scope: "offline_labeled_rule_evaluation", Tuning: tuning.Provenance, Evaluation: evaluation.Provenance, BaselineRuleSHA256: ruleHash(in.BaselineRule), CandidateRuleSHA256: ruleHash(in.CandidateRule), TuningComparison: compare(tuning.Events, in.BaselineRule, in.CandidateRule, in.TimestampProvenanceConfirmed), EvaluationComparison: compare(evaluation.Events, in.BaselineRule, in.CandidateRule, in.TimestampProvenanceConfirmed), Evidence: []Evidence{}, NextValidationPriorities: []Priority{}, Warnings: []string{"offline_only", "labels_supplied_by_uploader", "held_out_status_declared_by_uploader", "candidate_requires_independent_live_validation"}}
	priorities := map[string][]string{"missed_attack": {}, "false_positive": {}, "missing_fields": {}}
	for _, event := range evaluation.Events {
		baseline, _ := match(event, in.BaselineRule)
		candidate, missing := match(event, in.CandidateRule)
		out.Evidence = append(out.Evidence, Evidence{EventID: event.EventID, Label: event.Label, Baseline: baseline, Candidate: candidate, MissingFields: missing})
		if candidate == "unknown" {
			priorities["missing_fields"] = append(priorities["missing_fields"], event.EventID)
		} else if event.Label == "attack" && candidate == "no_match" {
			priorities["missed_attack"] = append(priorities["missed_attack"], event.EventID)
		} else if event.Label == "benign" && candidate == "match" {
			priorities["false_positive"] = append(priorities["false_positive"], event.EventID)
		}
	}
	for _, kind := range []string{"missing_fields", "missed_attack", "false_positive"} {
		if len(priorities[kind]) > 0 {
			out.NextValidationPriorities = append(out.NextValidationPriorities, Priority{Kind: kind, EventIDs: priorities[kind]})
		}
	}
	if evaluation.Provenance.Attacks == 0 || evaluation.Provenance.Benign == 0 {
		out.Warnings = append(out.Warnings, "evaluation_missing_attack_or_benign_class")
	}
	if !in.TimestampProvenanceConfirmed {
		out.Warnings = append(out.Warnings, "mttd_unverified")
	}
	if in.TimestampProvenanceConfirmed && (out.EvaluationComparison.Baseline.MTTDSeconds == nil || out.EvaluationComparison.Candidate.MTTDSeconds == nil) {
		out.Warnings = append(out.Warnings, "mttd_incomplete_timestamps")
	}
	return out, nil
}

// Suggest consults only the tuning set. It adds exact conditions supported by
// missed attack logs which match no benign tuning event. These can overfit and
// are proposals, never asserted as deployable security controls.
func Suggest(tuningLogs string, baseline Rule) (*Suggestion, error) {
	if err := ValidateRule(baseline); err != nil {
		return nil, err
	}
	tuning, err := ParseDataset(tuningLogs)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(baseline)
	var candidate Rule
	_ = json.Unmarshal(raw, &candidate)
	out := &Suggestion{CandidateRule: candidate, Tuning: tuning.Provenance, AddedConditions: []Condition{}, UnresolvedEventIDs: []string{}, Warnings: []string{"tuning_only", "exact_value_proposals_can_overfit", "review_candidate_before_held_out_evaluation"}}
	if tuning.Provenance.Benign == 0 {
		out.Warnings = append(out.Warnings, "tuning_has_no_benign_controls")
		for _, event := range tuning.Events {
			state, _ := match(event, baseline)
			if event.Label == "attack" && state != "match" {
				out.UnresolvedEventIDs = append(out.UnresolvedEventIDs, event.EventID)
			}
		}
		return out, nil
	}
	controlValues := map[string]map[string]bool{}
	controlPresence := map[string]int{}
	for _, event := range tuning.Events {
		if event.Label != "benign" {
			continue
		}
		for field, raw := range event.Fields {
			value, _ := scalar(raw)
			if controlValues[field] == nil {
				controlValues[field] = map[string]bool{}
			}
			controlValues[field][value] = true
			controlPresence[field]++
		}
	}
	for _, event := range tuning.Events {
		state, _ := match(event, out.CandidateRule)
		if event.Label != "attack" || state == "match" {
			continue
		}
		if len(out.CandidateRule.Any) >= MaxBranches || len(out.AddedConditions) >= 8 {
			out.UnresolvedEventIDs = append(out.UnresolvedEventIDs, event.EventID)
			continue
		}
		fields := make([]string, 0, len(event.Fields))
		for field := range event.Fields {
			lower := strings.ToLower(field)
			if lower == "label" || lower == "event_id" || strings.Contains(lower, "timestamp") || strings.HasSuffix(lower, "_id") || lower == "id" {
				continue
			}
			fields = append(fields, field)
		}
		sort.Strings(fields)
		added := false
		for _, field := range fields {
			value, _ := scalar(event.Fields[field])
			if value == "" || len(value) > 1024 {
				continue
			}
			condition := Condition{Field: field, Op: "equals", Value: value, CaseSensitive: true}
			// Constant-time lookup against pre-normalized benign controls replaces
			// an unbounded attack x field x control scan. Missing fields are unsafe.
			safe := controlPresence[field] == tuning.Provenance.Benign && !controlValues[field][value]
			if safe && len(out.CandidateRule.Any) < MaxBranches && len(out.AddedConditions) < 8 {
				out.CandidateRule.Any = append(out.CandidateRule.Any, Branch{All: []Condition{condition}})
				out.AddedConditions = append(out.AddedConditions, condition)
				added = true
				break
			}
		}
		if !added {
			out.UnresolvedEventIDs = append(out.UnresolvedEventIDs, event.EventID)
		}
	}
	if len(out.AddedConditions) > 0 {
		out.CandidateRule.Name = baseline.Name
		if utf8.RuneCountInString(out.CandidateRule.Name) > 110 {
			out.CandidateRule.Name = string([]rune(out.CandidateRule.Name)[:110])
		}
		out.CandidateRule.Name += " candidate"
	}
	if tuning.Provenance.Benign == 0 {
		out.Warnings = append(out.Warnings, "tuning_has_no_benign_controls")
	}
	return out, nil
}

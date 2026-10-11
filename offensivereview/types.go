// Package offensivereview reviews one stored scanner candidate at a time. It
// deliberately has no planner, tool executor, filesystem or network capability.
package offensivereview

import "github.com/Autumn-27/norma/llm"

const (
	KindAPI    = "api"
	KindSource = "source"

	StatusConfirmedStatic        = "confirmed_static"
	StatusRejected               = "rejected"
	StatusInsufficientEvidence   = "insufficient_evidence"
	StatusAuthRequired           = "auth_required"
	StatusNeedsDynamicValidation = "needs_dynamic_validation"
)

// Evidence is a bounded excerpt prepared by the caller. SHA256 identifies the
// original artifact; Ref identifies this particular excerpt within the input.
type Evidence struct {
	Ref       string `json:"ref"`
	Text      string `json:"text"`
	SHA256    string `json:"sha256,omitempty"`
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
}

type Candidate struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Kind     string     `json:"kind"`
	RuleID   string     `json:"rule_id,omitempty"`
	File     string     `json:"file,omitempty"`
	Line     int        `json:"line,omitempty"`
	Message  string     `json:"message,omitempty"`
	Evidence []Evidence `json:"evidence"`
}

// Result is a candidate review, not a finding or a claim of reproduction.
// ConfirmedStatic means a source-code defect supported by the provided excerpts;
// it does not mean runtime exploitation was attempted or succeeded.
type Result struct {
	CandidateID  string   `json:"candidate_id"`
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	Rationale    string   `json:"rationale"`
	EvidenceRefs []string `json:"evidence_refs"`
	Limitations  []string `json:"limitations"`
}

type Metrics struct {
	ModelCalls     int       `json:"model_calls"`
	ModelElapsedMS int64     `json:"model_elapsed_ms"`
	Usage          llm.Usage `json:"usage"`
}

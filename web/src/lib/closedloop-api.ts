import { http } from "@/lib/api";

export interface LoopCondition {
  field: string;
  op: "equals" | "contains";
  value: string;
  case_sensitive: boolean;
}
export interface LoopRule {
  name: string;
  any: { all: LoopCondition[] }[];
}
export interface LoopInput {
  scenario: string;
  finding_id?: string;
  case_id?: string;
  baseline_rule: LoopRule;
  candidate_rule: LoopRule;
  tuning_logs: string;
  evaluation_logs: string;
  notes: string;
  timestamp_provenance_confirmed: boolean;
}
export interface LoopMetrics {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  unknown_attack: number;
  unknown_benign: number;
  precision: number | null;
  recall: number | null;
  false_positive_rate: number | null;
  accuracy: number | null;
  mttd_seconds: number | null;
  timed_detections: number;
}
export interface LoopProvenance {
  sha256: string;
  events: number;
  attacks: number;
  benign: number;
}
export interface LoopComparison {
  baseline: LoopMetrics;
  candidate: LoopMetrics;
}
export interface LoopResult {
  engine: string;
  scope: "offline_labeled_rule_evaluation";
  tuning: LoopProvenance;
  evaluation: LoopProvenance;
  baseline_rule_sha256: string;
  candidate_rule_sha256: string;
  tuning_comparison: LoopComparison;
  evaluation_comparison: LoopComparison;
  evidence: {
    event_id: string;
    label: "attack" | "benign";
    baseline: string;
    candidate: string;
    missing_fields: string[];
  }[];
  next_validation_priorities: { kind: string; event_ids: string[] }[];
  warnings: string[];
}
export interface LoopSuggestion {
  candidate_rule: LoopRule;
  tuning: LoopProvenance;
  added_conditions: LoopCondition[];
  unresolved_event_ids: string[];
  warnings: string[];
}
export interface ClosedLoopIteration {
  id: string;
  input: LoopInput;
  result: LoopResult;
  finding_snapshot?: unknown;
  case_snapshot?: unknown;
  created_at: string;
}
export interface ClosedLoopSummary {
  id: string;
  scenario: string;
  finding_id?: string;
  case_id?: string;
  comparison: LoopComparison;
  evaluation: LoopProvenance;
  created_at: string;
}

export const closedloopApi = {
  suggest: (tuning_logs: string, baseline_rule: LoopRule) =>
    http<LoopSuggestion>("/closed-loop/suggest", {
      method: "POST",
      body: JSON.stringify({ tuning_logs, baseline_rule }),
    }),
  evaluate: (input: LoopInput) =>
    http<LoopResult>("/closed-loop/evaluate", { method: "POST", body: JSON.stringify(input) }),
  save: (input: LoopInput) =>
    http<ClosedLoopIteration>("/closed-loop/iterations", { method: "POST", body: JSON.stringify(input) }),
  list: () => http<{ iterations: ClosedLoopSummary[] }>("/closed-loop/iterations?limit=20"),
  get: (id: string) => http<ClosedLoopIteration>(`/closed-loop/iterations/${encodeURIComponent(id)}`),
  export: (id: string) => http<ClosedLoopIteration>(`/closed-loop/iterations/${encodeURIComponent(id)}/export`),
};

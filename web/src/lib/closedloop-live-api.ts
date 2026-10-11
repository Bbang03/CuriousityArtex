import { http } from "@/lib/api";
import type { LoopRule } from "@/lib/closedloop-api";
import type { DefenseAssessment, DefenseExecution, DefenseExecutionInput } from "@/lib/security-api";
import type { FindingRetest } from "@/lib/types";

export interface LiveCycleInput {
  request_id: string;
  scenario: string;
  finding_id: string;
  defense: Omit<DefenseExecutionInput, "notes">;
  baseline_rule: LoopRule;
  notes: string;
  log_target?: string;
  log_path?: string;
}

export interface LiveShadowResult {
  scope: string;
  engine: string;
  query: string;
  complete: boolean;
  truncated: number;
  total_rows: number;
  correlation_id: string;
  baseline_rule_sha256: string;
  candidate_rule_sha256: string;
  query_started_at: string;
  query_finished_at: string;
  warnings: string[];
  collected_at: string;
  window_start: string;
  window_end: string;
  events: { event_id: string; occurred_at: string; baseline: string; candidate: string; raw?: unknown }[];
}
export interface LiveCycleObservation {
  id: string;
  phase: "baseline" | "rerun";
  execution_id: string;
  assessment_id: string;
  rule_revision: number;
  native_rule_refs?: { detection_rule_id: string; rule_sha256: string }[];
  native: Omit<DefenseAssessment, "evidence"> & { evidence: DefenseAssessment["evidence"] | null };
  shadow: LiveShadowResult;
  evidence_sha256: string;
  created_at: string;
}
export interface LiveCycle {
  id: string;
  finding_id: string;
  scenario: string;
  status: string;
  revision: number;
  baseline_rule: LoopRule;
  candidate_rule: LoopRule | null;
  baseline: DefenseExecution;
  current: DefenseExecution | null;
  log_target: string;
  log_path: string;
  remediation_note: string;
  observations: LiveCycleObservation[];
  comparison: {
    comparable: boolean;
    reasons: string[];
    baseline_native_detection: string;
    current_native_detection: string;
    baseline_shadow_detection: string;
    candidate_shadow_detection: string;
    candidate_native_rule_detection: "detected" | "not_attributed";
    precision: null;
    recall: null;
    false_positive_rate: null;
    mttd_seconds: null;
  };
  created_at: string;
  updated_at: string;
}
export interface LiveCycleSummary {
  id: string;
  scenario: string;
  finding_id: string;
  status: string;
  revision: number;
  created_at: string;
  updated_at: string;
}

const cyclePath = (id: string) => `/closed-loop/live-cycles/${encodeURIComponent(id)}`;
export const liveLoopApi = {
  list: () => http<{ cycles: LiveCycleSummary[] }>("/closed-loop/live-cycles"),
  create: (input: LiveCycleInput) =>
    http<{ cycle: LiveCycle; execution: DefenseExecution; retest: FindingRetest }>("/closed-loop/live-cycles", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  get: (id: string) => http<LiveCycle>(cyclePath(id)),
  collect: (id: string) => http<LiveCycle>(`${cyclePath(id)}/collect`, { method: "POST" }),
  suggest: (id: string) =>
    http<{ candidate_rule: LoopRule; warnings: string[]; audit_event_ids: string[] }>(`${cyclePath(id)}/suggest`, {
      method: "POST",
    }),
  saveCandidate: (id: string, input: { expected_revision: number; rule: LoopRule; note: string }) =>
    http<LiveCycle>(`${cyclePath(id)}/candidate`, { method: "PUT", body: JSON.stringify(input) }),
  rerun: (id: string, expectedRevision: number) =>
    http<{ cycle: LiveCycle; execution: DefenseExecution; retest: FindingRetest }>(`${cyclePath(id)}/rerun`, {
      method: "POST",
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  stop: (id: string) => http<LiveCycle>(`${cyclePath(id)}/stop`, { method: "POST" }),
  export: (id: string) => http<Blob>(`${cyclePath(id)}/export`, undefined, "blob"),
};

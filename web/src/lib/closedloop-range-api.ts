import { http } from "@/lib/api";
import type { LoopRule } from "@/lib/closedloop-api";

export interface RangeScenario {
  id: string;
  kind?: string;
  name: string;
  technique: string;
  description: string;
}

export interface ChainRule {
  kind: "scheduled_task_chain";
  name: string;
  profile: "powershell_broad" | "task_behavior";
}

export type RangeRule = LoopRule | ChainRule;

export interface RangeExplanation {
  summary: string;
  causes: string[];
  evidence: string[];
  improvements: string[];
  limitations: string[];
}

export const isChainRule = (rule: RangeRule | null | undefined): rule is ChainRule =>
  Boolean(rule && "kind" in rule && rule.kind === "scheduled_task_chain");

export interface RangeMetrics {
  true_positives: number;
  false_negatives: number;
  false_positives: number;
  true_negatives: number;
  unknown: number;
  attack_total: number;
  benign_total: number;
}

export interface RangeCase {
  case_id: string;
  label: string;
  expected: "attack" | "benign";
  verdict: "detected" | "missed" | "false_positive" | "true_negative" | "unknown";
  execution_verified: boolean;
  alert_count: number;
  latency_seconds: number | null;
  reason: string;
  stages: {
    name: string;
    status: "observed" | "missing" | "unknown" | "verified";
    time: string | null;
    evidence: string;
  }[];
}

export interface RangeTimelineEvent {
  time: string;
  case_id: string;
  source: string;
  event_code: string;
  action: string;
  summary: string;
  process_image?: string;
}

export interface RangeStatus {
  configured: boolean;
  ready: boolean;
  message: string;
  environment?: { name: string; host: string; telemetry_source: string };
  scenarios?: RangeScenario[];
}

export interface RangeEvidence {
  complete: boolean;
  audit_count: number;
  alert_count: number;
  detected_scenarios: string[];
  missed_scenarios: string[];
  unknown_scenarios: string[];
  events: unknown[];
  warnings: string[];
  metrics?: RangeMetrics;
  cases?: RangeCase[];
  timeline?: RangeTimelineEvent[];
  analysis?: { summary: string; gaps: string[]; recommendations: string[] };
}

export interface RangeRun {
  id: string;
  kind?: string;
  status: string;
  started_at?: string | null;
  finished_at?: string | null;
  results: { scenario_id: string; name: string; status: string; exit_code: number | null; summary: string }[];
  evidence: RangeEvidence | null;
}

export interface RangeCycle {
  id: string;
  kind?: string;
  name: string;
  status: string;
  revision: number;
  scenario_ids: string[];
  baseline_rule: RangeRule;
  candidate_rule: RangeRule | null;
  candidate_note?: string;
  candidate_explanation?: RangeExplanation | null;
  baseline: RangeRun;
  current: RangeRun | null;
  comparison: {
    comparable: boolean;
    baseline_detected: number;
    current_detected: number;
    total_scenarios: number;
    reasons: string[];
    kind?: string;
    common_case_ids?: string[];
    baseline_metrics?: RangeMetrics | null;
    current_metrics?: RangeMetrics | null;
    heldout_variant?: RangeCase | null;
  };
  error?: string;
  created_at: string;
}

const base = "/closed-loop/range";
const cyclePath = (id: string) => `${base}/cycles/${encodeURIComponent(id)}`;

export const rangeLoopApi = {
  status: () => http<RangeStatus>(`${base}/status`),
  list: () => http<{ cycles: RangeCycle[] }>(`${base}/cycles`),
  create: (input: { request_id: string; scenario_ids: string[]; name: string }) =>
    http<RangeCycle>(`${base}/cycles`, { method: "POST", body: JSON.stringify(input) }),
  get: (id: string) => http<RangeCycle>(cyclePath(id)),
  collect: (id: string) => http<RangeCycle>(`${cyclePath(id)}/collect`, { method: "POST" }),
  suggest: (id: string) =>
    http<{
      candidate_rule: RangeRule;
      warnings: string[];
      explanation?: RangeExplanation;
    }>(`${cyclePath(id)}/suggest`, { method: "POST" }),
  candidate: (id: string, input: { expected_revision: number; rule: RangeRule; note: string }) =>
    http<RangeCycle>(`${cyclePath(id)}/candidate`, { method: "POST", body: JSON.stringify(input) }),
  rerun: (id: string, expectedRevision: number) =>
    http<RangeCycle>(`${cyclePath(id)}/rerun`, {
      method: "POST",
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  export: (id: string) => http<Blob>(`${cyclePath(id)}/export`, undefined, "blob"),
};

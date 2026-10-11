import { HttpError, http } from "@/lib/api";

export type AssessmentKind = "api" | "source";
export type ApiInputMode = "openapi" | "url" | "har";
export type AssessmentStatus = "queued" | "running" | "completed" | "failed" | "interrupted";

export interface AssessmentDiscovery {
  summary?: string;
  warnings?: string[];
  requests?: number;
  operations?: number;
  [key: string]: unknown;
}

export interface AssessmentTarget {
  id: string;
  kind: AssessmentKind;
  name: string;
  origin?: "upload" | "example";
  input_mode?: ApiInputMode;
  discovery?: AssessmentDiscovery;
  url?: string;
  scope_url?: string;
  source_path?: string;
  revision?: string;
  sha256?: string;
  file_count?: number;
  languages?: string[];
  operations?: { id: string; method: string; path: string; source?: string; confidence?: "observed" | "candidate" }[];
  ready: boolean;
  detail?: string;
}

export interface AssessmentTool {
  id: string;
  version?: string;
  available: boolean;
}

export interface AssessmentCandidate {
  id: string;
  title: string;
  severity: string;
  verification: "candidate";
  rule_id?: string;
  file?: string;
  line?: number;
  message: string;
  evidence?: unknown;
}

export interface AssessmentArtifact {
  name: string;
  path?: string;
  sha256?: string;
}

export interface AssessmentRun {
  id: string;
  kind: AssessmentKind;
  target_id: string;
  status: AssessmentStatus;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  tool: string;
  tool_version?: string;
  target: string | Record<string, unknown>;
  target_snapshot?: AssessmentTarget;
  operation_ids?: string[];
  source_revision?: string;
  summary?: string;
  candidates: AssessmentCandidate[];
  limitations: string[];
  artifacts: AssessmentArtifact[];
  task_id?: string;
  error?: string;
}

export interface AssessmentCatalog {
  targets: AssessmentTarget[];
  tools: AssessmentTool[];
  detail?: string;
  message?: string;
}

const runPath = (id: string) => `/offensive/runs/${encodeURIComponent(id)}`;

async function uploadTarget(input: {
  kind: AssessmentKind;
  name: string;
  base_url?: string;
  har_origin?: string;
  input_mode?: ApiInputMode;
  file?: File;
}) {
  const form = new FormData();
  form.append("kind", input.kind);
  form.append("name", input.name);
  if (input.base_url) form.append("base_url", input.base_url);
  if (input.har_origin) form.append("har_origin", input.har_origin);
  if (input.input_mode) form.append("input_mode", input.input_mode);
  if (input.file) form.append("file", input.file);
  const token = typeof window === "undefined" ? null : localStorage.getItem("artex_token");
  const response = await fetch("/api/offensive/targets", {
    method: "POST",
    body: form,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (response.status === 401) {
    localStorage.removeItem("artex_token");
    document.cookie = "artex_token=; path=/; max-age=0";
    window.location.href = "/login";
    throw new Error("인증되지 않았습니다");
  }
  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as { error?: unknown };
    throw new HttpError(
      typeof payload.error === "string" ? payload.error : `대상 등록 실패 (${response.status})`,
      response.status,
    );
  }
  return response.json() as Promise<AssessmentTarget>;
}

export const offensiveApi = {
  catalog: () => http<AssessmentCatalog>("/offensive/catalog"),
  list: () => http<{ runs: AssessmentRun[] }>("/offensive/runs"),
  get: (id: string) => http<AssessmentRun>(runPath(id)),
  uploadTarget,
  create: (kind: AssessmentKind, targetId: string, scope?: { operation_ids?: string[]; bearer_token?: string }) =>
    http<AssessmentRun>("/offensive/runs", {
      method: "POST",
      body: JSON.stringify({ kind, target_id: targetId, ...scope }),
    }),
  review: (id: string, profileIds?: number[]) =>
    http<{ task_id: string; run: AssessmentRun }>(`${runPath(id)}/review`, {
      method: "POST",
      body: JSON.stringify(profileIds?.length ? { llm_profile_ids: profileIds } : {}),
    }),
  artifact: (id: string, name: string) =>
    http<Blob>(`${runPath(id)}/artifacts/${encodeURIComponent(name)}`, undefined, "blob"),
};

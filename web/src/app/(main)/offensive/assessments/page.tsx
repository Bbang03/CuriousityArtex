"use client";

import * as React from "react";

import Link from "next/link";

import {
  ArrowLeftIcon,
  ArrowUpRightIcon,
  CodeXmlIcon,
  DownloadIcon,
  FileSearchIcon,
  GlobeIcon,
  LoaderCircleIcon,
  PlayIcon,
  RefreshCwIcon,
  UploadIcon,
} from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import {
  type ApiInputMode,
  type AssessmentCatalog,
  type AssessmentDiscovery,
  type AssessmentKind,
  type AssessmentRun,
  type AssessmentStatus,
  type AssessmentTarget,
  offensiveApi,
} from "@/lib/offensive-api";
import type { LLMProfile } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATUS: Record<AssessmentStatus, string> = {
  queued: "대기 중",
  running: "진단 중",
  completed: "도구 진단 완료",
  failed: "진단 실패",
  interrupted: "진단 중단",
};
const KINDS: Record<AssessmentKind, { title: string; tool: string; description: string }> = {
  api: {
    title: "API 진단",
    tool: "Schemathesis",
    description: "명세·URL·HAR에서 API 요청을 등록하고, 선택한 요청의 응답·입력 처리를 확인합니다.",
  },
  source: {
    title: "소스 코드 진단",
    tool: "Semgrep",
    description: "소스 ZIP을 등록해 Java·Python·JavaScript·TypeScript 코드의 의심 위치를 분석합니다.",
  },
};
const MAX_OPERATIONS = 40;
const INPUT_MODES: Record<ApiInputMode, { title: string; description: string; addressLabel: string }> = {
  openapi: {
    title: "OpenAPI 명세",
    description: "명세에 정의된 API 요청과 응답 형식을 검사합니다.",
    addressLabel: "API 기본 주소",
  },
  url: {
    title: "URL 탐색",
    description: "시작 주소의 링크 등에서 API 후보 경로를 찾습니다.",
    addressLabel: "탐색 시작 주소",
  },
  har: {
    title: "HAR 업로드",
    description: "브라우저에서 저장한 요청 기록에서 API 후보 경로를 찾습니다.",
    addressLabel: "HAR에서 선택할 API 주소·경로",
  },
};
const FILE_INPUTS = {
  source: {
    maxMiB: 20,
    accept: ".zip",
    extension: /\.zip$/i,
    label: "소스 ZIP · 최대 20 MiB",
    error: "소스 코드를 담은 ZIP 파일을 선택하세요.",
  },
  openapi: {
    maxMiB: 8,
    accept: ".json,.yaml,.yml",
    extension: /\.(json|ya?ml)$/i,
    label: "OpenAPI 명세 파일 · JSON / YAML, 최대 8 MiB",
    error: "OpenAPI JSON 또는 YAML 파일을 선택하세요.",
  },
  har: {
    maxMiB: 16,
    accept: ".har,.json",
    extension: /\.(har|json)$/i,
    label: "HAR 파일 · HAR / JSON, 최대 16 MiB",
    error: "브라우저 요청 기록을 담은 HAR 또는 JSON 파일을 선택하세요.",
  },
};

function isDiscoveredApi(target?: AssessmentTarget) {
  return target?.input_mode === "url" || target?.input_mode === "har";
}

function candidateNotice(run: AssessmentRun) {
  if (run.kind === "source")
    return "정적 분석 결과는 실행 흐름과 입력 조건 검토가 필요합니다. 후보 발견은 동적 재현 성공을 뜻하지 않습니다.";
  if (isDiscoveredApi(run.target_snapshot))
    return "서버 오류 응답은 검토할 후보이며 취약점 확정을 뜻하지 않습니다. 명세가 없으므로 응답 형식의 일치 여부는 검사하지 않았습니다. 요청·응답과 실제 영향을 검토하세요.";
  return "명세 위반이나 비정상 응답만으로 보안 취약점이 확정되지는 않습니다. 요청·응답과 실제 영향을 검토해야 합니다.";
}

function DiscoveryDetails({ discovery }: { discovery?: AssessmentDiscovery }) {
  if (!discovery) return null;
  return (
    <div className="space-y-2 text-muted-foreground text-xs">
      {discovery.summary && <p>{discovery.summary}</p>}
      {typeof discovery.requests === "number" && <p>탐색 요청: {discovery.requests}회</p>}
      {!!discovery.warnings?.length && (
        <ul className="list-disc space-y-1 pl-5">
          {[...new Set(discovery.warnings)].map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function allowedOperations(target?: AssessmentTarget) {
  return (target?.operations ?? []).filter((operation) => ["GET", "HEAD"].includes(operation.method.toUpperCase()));
}

function runTargetName(run: AssessmentRun, catalog: AssessmentCatalog | null) {
  return (
    run.target_snapshot?.name || catalog?.targets.find((target) => target.id === run.target_id)?.name || run.target_id
  );
}

function isActive(run: AssessmentRun) {
  return run.status === "queued" || run.status === "running";
}

function formatTime(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ko-KR");
}

function evidenceText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2) ?? "";
}

function errorText(value: unknown): string {
  return value instanceof Error ? value.message : "요청을 완료하지 못했습니다. 잠시 후 다시 시도하세요.";
}

function RunStatus({ run }: { run: AssessmentRun }) {
  return (
    <Badge variant={run.status === "failed" || run.status === "interrupted" ? "destructive" : "secondary"}>
      {isActive(run) && <LoaderCircleIcon className="mr-1 size-3 animate-spin" />}
      {STATUS[run.status] ?? run.status}
    </Badge>
  );
}

export default function OffensiveAssessmentsPage() {
  const [kind, setKind] = React.useState<AssessmentKind>("api");
  const [inputMode, setInputMode] = React.useState<ApiInputMode>("openapi");
  const [catalog, setCatalog] = React.useState<AssessmentCatalog | null>(null);
  const [runs, setRuns] = React.useState<AssessmentRun[]>([]);
  const [selected, setSelected] = React.useState<AssessmentRun | null>(null);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [profileId, setProfileId] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [starting, setStarting] = React.useState(false);
  const [reviewing, setReviewing] = React.useState(false);
  const [downloading, setDownloading] = React.useState("");
  const [openingId, setOpeningId] = React.useState("");
  const [error, setError] = React.useState("");
  const [catalogError, setCatalogError] = React.useState("");
  const [pollError, setPollError] = React.useState("");
  const [targetId, setTargetId] = React.useState("");
  const [uploadName, setUploadName] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [harOrigin, setHarOrigin] = React.useState("");
  const [uploadFile, setUploadFile] = React.useState<File | null>(null);
  const [uploading, setUploading] = React.useState(false);
  const [uploadError, setUploadError] = React.useState("");
  const [uploadNotice, setUploadNotice] = React.useState("");
  const [operationIds, setOperationIds] = React.useState<string[]>([]);
  const [operationTargetId, setOperationTargetId] = React.useState("");
  const [bearerToken, setBearerToken] = React.useState("");
  const uploadFileRef = React.useRef<HTMLInputElement>(null);
  const selectionSeq = React.useRef(0);
  const refreshSeq = React.useRef(0);
  const profileSelectId = React.useId();
  const targetSelectId = React.useId();
  const uploadNameId = React.useId();
  const baseUrlId = React.useId();
  const harOriginId = React.useId();
  const uploadFileId = React.useId();
  const bearerId = React.useId();

  const refresh = React.useCallback(async () => {
    const seq = ++refreshSeq.current;
    setLoading(true);
    const results = await Promise.allSettled([offensiveApi.catalog(), offensiveApi.list(), api.llmProfiles()]);
    if (seq !== refreshSeq.current) return;
    const [targetResult, historyResult, profileResult] = results;
    if (targetResult.status === "fulfilled") {
      setCatalog(targetResult.value);
      setCatalogError("");
    } else {
      setCatalog(null);
      setCatalogError(errorText(targetResult.reason));
    }
    if (historyResult.status === "fulfilled") {
      const history = historyResult.value.runs ?? [];
      setRuns(history);
      setError("");
      setSelected((previous) =>
        previous ? (history.find((run) => run.id === previous.id) ?? previous) : (history[0] ?? null),
      );
    } else {
      setError(errorText(historyResult.reason));
    }
    if (profileResult.status === "fulfilled") setProfiles(profileResult.value);
    setLoading(false);
  }, []);

  React.useEffect(() => {
    void refresh();
    return () => {
      refreshSeq.current += 1;
      selectionSeq.current += 1;
    };
  }, [refresh]);

  const active = runs.some(isActive) || (selected ? isActive(selected) : false);
  React.useEffect(() => {
    if (!active) return;
    let alive = true;
    let polling = false;
    const selectedId = selected?.id;
    const seq = selectionSeq.current;
    const poll = async () => {
      if (polling) return;
      polling = true;
      try {
        const [history, detail] = await Promise.all([
          offensiveApi.list(),
          selectedId ? offensiveApi.get(selectedId) : Promise.resolve(null),
        ]);
        if (!alive) return;
        setRuns(history.runs ?? []);
        if (detail && seq === selectionSeq.current) {
          setSelected((previous) => ({
            ...detail,
            task_id: detail.task_id || (previous?.id === detail.id ? previous.task_id : undefined),
          }));
        }
        setPollError("");
      } catch (cause) {
        if (alive) setPollError(`실행 상태 갱신 실패: ${errorText(cause)}`);
      } finally {
        polling = false;
      }
    };
    const timer = setInterval(() => void poll(), 3000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [active, selected?.id]);

  const targets = React.useMemo(() => (catalog?.targets ?? []).filter((item) => item.kind === kind), [catalog, kind]);
  const target = targets.find((item) => item.id === targetId);
  const operations = allowedOperations(target);
  const customApi = kind === "api" && target?.origin === "upload";
  const needsUploadFile = kind === "source" || inputMode !== "url";
  const fileInput = kind === "source" ? FILE_INPUTS.source : FILE_INPUTS[inputMode === "har" ? "har" : "openapi"];
  const isUrlRegistration = kind === "api" && inputMode === "url";
  const RegisterIcon = isUrlRegistration ? GlobeIcon : UploadIcon;
  const registerLabel = isUrlRegistration ? "URL에서 API 찾기" : "업로드하고 대상 등록";
  const registeringLabel = isUrlRegistration ? "URL에서 경로 탐색 중…" : "업로드·확인 중…";
  const discoveredApi = isDiscoveredApi(target);
  const startLabel = discoveredApi ? "탐색한 요청 검사 시작" : `${KINDS[kind].title} 시작`;
  React.useEffect(() => {
    if (!targets.some((item) => item.id === targetId)) setTargetId(targets[0]?.id ?? "");
  }, [targets, targetId]);
  React.useEffect(() => {
    if (!target || target.id === operationTargetId) return;
    setOperationTargetId(target.id);
    setOperationIds(
      allowedOperations(target)
        .slice(0, MAX_OPERATIONS)
        .map((operation) => operation.id),
    );
    setBearerToken("");
  }, [target, operationTargetId]);
  const candidates = selected?.candidates ?? [];
  const artifacts = selected?.artifacts ?? [];
  const selectedDiscoveredApi = isDiscoveredApi(selected?.target_snapshot);

  const changeKind = (next: AssessmentKind) => {
    if (next === kind) return;
    setKind(next);
    setTargetId("");
    setUploadFile(null);
    setUploadName("");
    setUploadError("");
    setUploadNotice("");
    setBearerToken("");
    if (uploadFileRef.current) uploadFileRef.current.value = "";
  };

  const changeInputMode = (next: ApiInputMode) => {
    setInputMode(next);
    setUploadFile(null);
    setUploadError("");
    setUploadNotice("");
    if (uploadFileRef.current) uploadFileRef.current.value = "";
  };

  const registerTarget = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if ((needsUploadFile && !uploadFile) || uploading) return;
    setUploadError("");
    setUploadNotice("");
    if (!uploadName.trim() || uploadName.trim().length > 100) {
      setUploadError("대상 이름은 1~100자로 입력하세요.");
      return;
    }
    if (needsUploadFile && uploadFile) {
      if (uploadFile.size > fileInput.maxMiB * 1024 * 1024) {
        setUploadError(`파일은 ${fileInput.maxMiB} MiB 이하여야 합니다.`);
        return;
      }
      if (!fileInput.extension.test(uploadFile.name)) {
        setUploadError(fileInput.error);
        return;
      }
    }
    if (kind === "api") {
      try {
        const url = new URL(baseUrl.trim());
        if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
          throw new Error("invalid URL");
        }
      } catch {
        setUploadError("HTTP(S) API 주소를 입력하세요. 주소에 계정·비밀번호·쿼리·해시를 넣지 마세요.");
        return;
      }
      if (inputMode === "har" && harOrigin.trim()) {
        try {
          const origin = new URL(harOrigin.trim());
          if (
            !["http:", "https:"].includes(origin.protocol) ||
            origin.username ||
            origin.password ||
            origin.search ||
            origin.hash ||
            !["", "/"].includes(origin.pathname)
          ) {
            throw new Error("invalid origin");
          }
        } catch {
          setUploadError("HAR 원본 주소는 HTTP(S) 서버 주소와 포트만 입력하세요. 경로·쿼리는 넣지 마세요.");
          return;
        }
      }
    }
    setUploading(true);
    try {
      const uploaded = await offensiveApi.uploadTarget({
        kind,
        name: uploadName.trim(),
        base_url: kind === "api" ? baseUrl.trim() : undefined,
        har_origin: kind === "api" && inputMode === "har" ? harOrigin.trim() || undefined : undefined,
        input_mode: kind === "api" ? inputMode : undefined,
        file: needsUploadFile ? (uploadFile ?? undefined) : undefined,
      });
      setCatalog((previous) => ({
        ...(previous ?? { tools: [] }),
        targets: [uploaded, ...(previous?.targets ?? []).filter((item) => item.id !== uploaded.id)],
      }));
      setTargetId(uploaded.id);
      setUploadFile(null);
      setUploadName("");
      if (uploadFileRef.current) uploadFileRef.current.value = "";
      setUploadNotice(`“${uploaded.name}” 등록 완료. 아래에서 범위를 확인하고 진단을 시작하세요.`);
    } catch (cause) {
      setUploadError(errorText(cause));
    } finally {
      setUploading(false);
    }
  };

  const start = async () => {
    if (!target?.ready || starting || (customApi && !operationIds.length)) return;
    setStarting(true);
    setError("");
    const seq = ++selectionSeq.current;
    try {
      const run = await offensiveApi.create(
        kind,
        target.id,
        customApi
          ? {
              operation_ids: operationIds,
              bearer_token: bearerToken.trim() || undefined,
            }
          : undefined,
      );
      setRuns((previous) => [run, ...previous.filter((item) => item.id !== run.id)]);
      if (seq === selectionSeq.current) setSelected(run);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBearerToken("");
      setStarting(false);
    }
  };

  const openRun = async (run: AssessmentRun) => {
    const seq = ++selectionSeq.current;
    setOpeningId(run.id);
    setError("");
    setPollError("");
    try {
      const detail = await offensiveApi.get(run.id);
      if (seq === selectionSeq.current) setSelected(detail);
    } catch (cause) {
      if (seq === selectionSeq.current) setError(errorText(cause));
    } finally {
      if (seq === selectionSeq.current) setOpeningId("");
    }
  };

  const review = async () => {
    if (!selected || reviewing) return;
    const id = selected.id;
    setReviewing(true);
    setError("");
    try {
      const result = await offensiveApi.review(id, profileId ? [Number(profileId)] : undefined);
      const run = { ...result.run, task_id: result.task_id };
      setSelected((previous) => (previous?.id === id ? run : previous));
      setRuns((previous) => previous.map((item) => (item.id === id ? run : item)));
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setReviewing(false);
    }
  };

  const download = async (runId: string, name: string) => {
    setDownloading(name);
    setError("");
    try {
      const blob = await offensiveApi.artifact(runId, name);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = name.split("/").pop() || "assessment-evidence";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setDownloading("");
    }
  };

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 pb-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <Link
            href="/offensive/"
            className="inline-flex items-center gap-1 text-muted-foreground text-xs hover:text-foreground"
          >
            <ArrowLeftIcon className="size-3" /> 진단 개요
          </Link>
          <h1 className="font-semibold text-xl tracking-tight">API · 소스 코드 진단</h1>
          <p className="text-muted-foreground text-sm">대상 등록·선택 → 도구 진단 → 근거 확인 → ARTEX 심층 검토</p>
        </div>
        <Button variant="outline" size="sm" disabled={loading || uploading || starting} onClick={() => void refresh()}>
          <RefreshCwIcon className={cn("size-4", loading && "animate-spin")} /> 새로고침
        </Button>
      </div>

      {(error || pollError) && (
        <Alert variant="destructive">
          <AlertDescription role="alert">{error || pollError}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">1. 진단 대상 등록·선택</CardTitle>
          <CardDescription>직접 등록한 대상이나 설치된 실습 예제를 선택해서 진단합니다.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            {(["api", "source"] as const).map((item) => {
              const info = KINDS[item];
              const count = catalog?.targets?.filter((entry) => entry.kind === item).length ?? 0;
              const Icon = item === "api" ? GlobeIcon : CodeXmlIcon;
              return (
                <button
                  key={item}
                  type="button"
                  aria-pressed={kind === item}
                  disabled={uploading || starting}
                  onClick={() => changeKind(item)}
                  className={cn(
                    "flex flex-col gap-3 rounded-lg border p-4 text-left transition-colors hover:bg-accent/50 focus-visible:outline-2 focus-visible:outline-ring",
                    kind === item && "border-primary bg-primary/5",
                  )}
                >
                  <div className="flex w-full items-center justify-between gap-3">
                    <span className="flex items-center gap-2 font-medium">
                      <Icon className="size-4" />
                      {info.title}
                    </span>
                    <Badge variant="outline">{loading && !catalog ? "확인 중" : `등록 대상 ${count}개`}</Badge>
                  </div>
                  <span className="text-muted-foreground text-sm">{info.description}</span>
                  <span className="font-medium text-xs">{info.tool} + ARTEX</span>
                </button>
              );
            })}
          </div>
          {catalogError && (
            <Alert>
              <AlertDescription>
                <p className="font-medium">진단 환경에 연결하지 못했습니다.</p>
                <p className="mt-1 break-words">{catalogError}</p>
                <p className="mt-1">
                  로컬 진단 환경을 준비한 뒤 새로고침하세요. 설치 방법은 배포 문서의 API·소스 코드 진단 가이드를
                  참고하세요.
                </p>
              </AlertDescription>
            </Alert>
          )}
          {(catalog?.message || catalog?.detail) && (
            <Alert>
              <AlertDescription>{catalog.message || catalog.detail}</AlertDescription>
            </Alert>
          )}
          <form onSubmit={(event) => void registerTarget(event)} className="space-y-3 rounded-lg border p-4">
            <div className="flex items-center gap-2 font-medium text-sm">
              <RegisterIcon className="size-4" /> 내 {kind === "api" ? "API" : "소스 코드"} 등록
            </div>
            {kind === "api" && (
              <fieldset className="space-y-2" disabled={uploading}>
                <legend className="mb-2 text-sm">API 요청을 준비하는 방법</legend>
                <div className="grid gap-2 sm:grid-cols-3">
                  {(["openapi", "url", "har"] as const).map((mode) => (
                    <button
                      key={mode}
                      type="button"
                      aria-pressed={inputMode === mode}
                      onClick={() => changeInputMode(mode)}
                      className={cn(
                        "rounded-md border px-3 py-2 text-left text-sm hover:bg-accent/50 focus-visible:outline-2 focus-visible:outline-ring",
                        inputMode === mode && "border-primary bg-primary/5",
                      )}
                    >
                      {INPUT_MODES[mode].title}
                    </button>
                  ))}
                </div>
                <p className="text-muted-foreground text-xs">{INPUT_MODES[inputMode].description}</p>
              </fieldset>
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor={uploadNameId}>대상 이름</Label>
                <Input
                  id={uploadNameId}
                  value={uploadName}
                  onChange={(event) => setUploadName(event.target.value)}
                  placeholder={kind === "api" ? "예: 주문 API 개발 서버" : "예: 주문 서비스 소스"}
                  required
                  maxLength={100}
                  disabled={uploading}
                />
              </div>
              {kind === "api" && (
                <div className="space-y-2">
                  <Label htmlFor={baseUrlId}>{INPUT_MODES[inputMode].addressLabel}</Label>
                  <Input
                    id={baseUrlId}
                    type="url"
                    value={baseUrl}
                    onChange={(event) => setBaseUrl(event.target.value)}
                    placeholder="http://host.docker.internal:8080/api"
                    required
                    maxLength={2048}
                    disabled={uploading}
                    autoComplete="off"
                  />
                </div>
              )}
              {kind === "api" && inputMode === "har" && (
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor={harOriginId}>HAR 원본 주소 · 주소가 다른 경우</Label>
                  <Input
                    id={harOriginId}
                    type="url"
                    value={harOrigin}
                    onChange={(event) => setHarOrigin(event.target.value)}
                    placeholder="예: http://localhost:18888"
                    maxLength={2048}
                    disabled={uploading}
                    autoComplete="off"
                  />
                  <p className="text-muted-foreground text-xs">
                    브라우저의 localhost 요청을 가져오려면 원본 주소에 localhost 주소, 위 API 주소에
                    host.docker.internal 주소를 입력하세요. 같은 경로를 진단 서버에서 접근할 주소로 연결합니다. 같으면
                    비워 두세요.
                  </p>
                </div>
              )}
              {needsUploadFile && (
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor={uploadFileId}>{fileInput.label}</Label>
                  <Input
                    id={uploadFileId}
                    ref={uploadFileRef}
                    type="file"
                    accept={fileInput.accept}
                    required
                    disabled={uploading}
                    onChange={(event) => {
                      setUploadFile(event.target.files?.[0] ?? null);
                      setUploadError("");
                      setUploadNotice("");
                    }}
                  />
                </div>
              )}
            </div>
            <p className="text-muted-foreground text-xs">
              {kind === "api"
                ? "진단할 권한이 있는 주소를 입력하세요. 이 컴퓨터의 API는 localhost 대신 host.docker.internal을 사용합니다. 등록한 GET·HEAD 요청을 선택해 실행합니다."
                : "Java·Python·JavaScript·TypeScript 소스를 분석합니다. 업로드한 코드는 실행하지 않습니다. .env·인증서·비밀 키와 의존성 폴더는 ZIP에서 제외하세요."}
            </p>
            {kind === "api" && inputMode === "url" && (
              <p className="text-muted-foreground text-xs">
                같은 서버·경로 범위에서 공개된 페이지를 제한적으로 탐색합니다. 로그인 뒤의 요청이나 JavaScript로
                생성되는 API는 HAR 업로드로 보완하세요. 찾은 경로가 모두 API인 것은 아닙니다.
              </p>
            )}
            {kind === "api" && inputMode === "har" && (
              <p className="text-muted-foreground text-xs">
                입력한 서버·경로에 해당하는 요청만 가져옵니다. HAR의 쿠키·인증 헤더와 요청 본문은 재사용하지 않습니다.
                진단에 필요한 Bearer 토큰은 대상 등록 후 별도로 입력하세요.
              </p>
            )}
            {uploadError && (
              <p role="alert" className="text-destructive text-sm">
                {uploadError}
              </p>
            )}
            {uploadNotice && (
              <p role="status" className="text-primary text-sm">
                {uploadNotice}
              </p>
            )}
            <Button
              type="submit"
              variant="outline"
              disabled={
                loading ||
                uploading ||
                !catalog ||
                (needsUploadFile && !uploadFile) ||
                !uploadName.trim() ||
                (kind === "api" && !baseUrl.trim())
              }
            >
              {uploading ? <LoaderCircleIcon className="size-4 animate-spin" /> : <RegisterIcon className="size-4" />}
              {uploading ? registeringLabel : registerLabel}
            </Button>
            {uploading && kind === "api" && inputMode === "url" && (
              <p role="status" className="text-muted-foreground text-xs">
                공개된 경로와 응답을 확인하고 있습니다. 탐색에는 최대 약 30초가 걸릴 수 있습니다.
              </p>
            )}
          </form>
          <div className="space-y-2">
            <Label htmlFor={targetSelectId}>진단할 대상</Label>
            <select
              id={targetSelectId}
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
              disabled={uploading || starting || !targets.length}
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              {!targets.length && <option value="">먼저 진단 대상을 등록하세요</option>}
              {targets.some((item) => item.origin === "upload") && (
                <optgroup label="내가 등록한 대상">
                  {targets
                    .filter((item) => item.origin === "upload")
                    .map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                        {item.ready ? "" : " (준비 필요)"}
                      </option>
                    ))}
                </optgroup>
              )}
              {targets.some((item) => item.origin !== "upload") && (
                <optgroup label="설치된 실습 예제">
                  {targets
                    .filter((item) => item.origin !== "upload")
                    .map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                        {item.ready ? "" : " (준비 필요)"}
                      </option>
                    ))}
                </optgroup>
              )}
            </select>
          </div>
          {target && (
            <div className="space-y-1 rounded-md bg-muted/50 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-medium">{target.name}</p>
                <Badge variant="outline">{target.origin === "upload" ? "직접 등록" : "실습 예제"}</Badge>
                {target.kind === "api" && (
                  <Badge variant="outline">{INPUT_MODES[target.input_mode ?? "openapi"].title}</Badge>
                )}
                <Badge variant={target.ready ? "secondary" : "destructive"}>
                  {target.ready ? "준비됨" : "준비 필요"}
                </Badge>
              </div>
              {(target.url || target.source_path) && (
                <p className="break-all font-mono text-muted-foreground text-xs">
                  {target.scope_url || target.url || target.source_path}
                </p>
              )}
              {target.revision && (
                <p className="break-all text-muted-foreground text-xs">소스 버전: {target.revision}</p>
              )}
              {target.detail && <p className="text-muted-foreground">{target.detail}</p>}
              {discoveredApi && (
                <p className="text-muted-foreground text-xs">
                  탐색한 GET·HEAD 요청 {operations.length}개 · 선택한 요청의 서버 오류를 검사합니다.
                </p>
              )}
              <DiscoveryDetails discovery={target.discovery} />
              {!!target.languages?.length && (
                <p className="text-muted-foreground text-xs">
                  {target.languages.join(" · ")}
                  {target.file_count != null ? ` · 소스 ${target.file_count}개` : ""}
                </p>
              )}
              {target.sha256 && (
                <details>
                  <summary className="cursor-pointer text-muted-foreground text-xs">등록 자료 식별값</summary>
                  <p className="mt-1 break-all font-mono text-xs">SHA-256: {target.sha256}</p>
                </details>
              )}
            </div>
          )}
          {customApi && (
            <div className="space-y-4 rounded-lg border p-4">
              <fieldset className="space-y-3" disabled={starting}>
                <legend className="font-medium text-sm">API 요청 범위 · {operationIds.length}개 선택</legend>
                <p className="text-muted-foreground text-xs">
                  {discoveredApi
                    ? `탐색한 GET·HEAD 중 최대 ${MAX_OPERATIONS}개를 실행합니다. 발견된 경로가 API로 정상 동작하는지는 응답을 검토해 확인하세요. 명세가 없어 응답 형식의 일치 여부는 검사하지 않습니다.`
                    : `업로드한 명세의 GET·HEAD 중 최대 ${MAX_OPERATIONS}개를 실행합니다. 경로·쿼리 입력값은 도구가 생성합니다.`}
                </p>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setOperationIds(operations.slice(0, MAX_OPERATIONS).map((operation) => operation.id))
                    }
                  >
                    {operations.length > MAX_OPERATIONS ? `앞 ${MAX_OPERATIONS}개 선택` : "전체 선택"}
                  </Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => setOperationIds([])}>
                    선택 해제
                  </Button>
                </div>
                <div className="max-h-56 space-y-1 overflow-y-auto">
                  {operations.map((operation) => {
                    const checked = operationIds.includes(operation.id);
                    return (
                      <label
                        key={operation.id}
                        className="flex cursor-pointer items-start gap-2 rounded px-2 py-2 hover:bg-muted/50"
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={!checked && operationIds.length >= MAX_OPERATIONS}
                          onChange={(event) =>
                            setOperationIds((previous) =>
                              event.target.checked
                                ? [...previous, operation.id]
                                : previous.filter((id) => id !== operation.id),
                            )
                          }
                          className="mt-0.5 size-4 shrink-0 accent-primary"
                        />
                        <span className="break-all font-mono text-xs">
                          {operation.method.toUpperCase()} {operation.path}
                        </span>
                        {discoveredApi && (
                          <Badge variant="outline" className="shrink-0 text-[10px]">
                            {operation.confidence === "observed" ? "요청 관측" : "경로 후보"}
                          </Badge>
                        )}
                      </label>
                    );
                  })}
                </div>
                {!operations.length && (
                  <p className="text-destructive text-xs">이 대상에는 실행 가능한 GET·HEAD 요청이 없습니다.</p>
                )}
              </fieldset>
              <div className="space-y-2">
                <Label htmlFor={bearerId}>Bearer 토큰 · 선택 사항</Label>
                <Input
                  id={bearerId}
                  type="password"
                  value={bearerToken}
                  onChange={(event) => setBearerToken(event.target.value)}
                  autoComplete="new-password"
                  placeholder="Bearer 접두어 없이 토큰만 입력"
                  maxLength={8192}
                  disabled={starting}
                />
                <p className="text-muted-foreground text-xs">
                  이번 도구 진단 요청에만 사용합니다. 입력값은 제출 후 지우며 ARTEX 검토에 전달하지 않습니다.
                </p>
              </div>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-3">
            <Button
              disabled={!target?.ready || starting || active || uploading || (customApi && !operationIds.length)}
              onClick={() => void start()}
            >
              {starting ? <LoaderCircleIcon className="size-4 animate-spin" /> : <PlayIcon className="size-4" />}
              {active ? "진행 중인 진단 완료 대기" : startLabel}
            </Button>
            <p className="text-muted-foreground text-xs">
              도구 진단은 LLM 없이 실행됩니다. AI 검토는 결과 확인 후 별도로 시작합니다.
            </p>
          </div>
          {active && (
            <p className="text-muted-foreground text-xs">
              도구 진단은 한 번에 한 개씩 실행됩니다. 현재 진단이 끝나면 다음 진단을 시작할 수 있습니다.
            </p>
          )}
          {!!catalog?.tools?.length && (
            <p className="text-muted-foreground text-xs">
              {catalog.tools
                .map((tool) => `${tool.id} ${tool.version || "버전 미확인"}${tool.available ? "" : " (사용 불가)"}`)
                .join(" · ")}
            </p>
          )}
        </CardContent>
      </Card>

      <div className="grid items-start gap-5 xl:grid-cols-[280px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">실행 이력</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {!runs.length && (
              <p className="text-muted-foreground text-sm">
                {loading ? "불러오는 중…" : "아직 실행한 진단이 없습니다."}
              </p>
            )}
            {runs.map((run) => (
              <button
                key={run.id}
                type="button"
                aria-pressed={selected?.id === run.id}
                disabled={openingId === run.id}
                onClick={() => void openRun(run)}
                className={cn(
                  "w-full space-y-2 rounded-lg border p-3 text-left hover:bg-accent/50",
                  selected?.id === run.id && "border-primary bg-primary/5",
                )}
              >
                <div className="flex items-center justify-between gap-2 font-medium text-sm">
                  {KINDS[run.kind]?.title ?? run.kind}
                  {openingId === run.id && <LoaderCircleIcon className="size-3 animate-spin" />}
                </div>
                <RunStatus run={run} />
                <p className="break-words text-sm">{runTargetName(run, catalog)}</p>
                <p className="text-muted-foreground text-xs">{formatTime(run.created_at)}</p>
              </button>
            ))}
          </CardContent>
        </Card>

        <div className="min-w-0 space-y-5">
          {!selected ? (
            <Card>
              <CardContent className="flex flex-col items-center gap-3 py-14 text-center text-muted-foreground">
                <FileSearchIcon className="size-8" />
                <p>진단을 시작하거나 실행 이력을 선택하세요.</p>
                <p className="text-xs">실제 도구 결과와 원본 근거가 여기에 표시됩니다.</p>
              </CardContent>
            </Card>
          ) : (
            <>
              <Card>
                <CardHeader>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="text-base">2. 진단 결과 · 근거 확인</CardTitle>
                    <RunStatus run={selected} />
                  </div>
                  <CardDescription className="break-all">실행 ID: {selected.id}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <dl className="grid gap-3 text-sm sm:grid-cols-2">
                    <div>
                      <dt className="text-muted-foreground text-xs">대상</dt>
                      <dd className="mt-1 break-all">
                        <span className="block font-medium">{runTargetName(selected, catalog)}</span>
                        <span className="mt-1 block text-muted-foreground text-xs">
                          {typeof selected.target === "string" ? selected.target : evidenceText(selected.target)}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground text-xs">분석 도구</dt>
                      <dd className="mt-1">
                        {selected.tool} {selected.tool_version}
                      </dd>
                    </div>
                    {selected.kind === "api" && (
                      <div>
                        <dt className="text-muted-foreground text-xs">요청 출처 · 검사 방식</dt>
                        <dd className="mt-1">
                          {INPUT_MODES[selected.target_snapshot?.input_mode ?? "openapi"].title} ·{" "}
                          {selectedDiscoveredApi ? "서버 오류 검사" : "명세 기반 검사"}
                        </dd>
                      </div>
                    )}
                    <div>
                      <dt className="text-muted-foreground text-xs">시작</dt>
                      <dd className="mt-1">{formatTime(selected.started_at || selected.created_at)}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground text-xs">종료</dt>
                      <dd className="mt-1">{formatTime(selected.finished_at)}</dd>
                    </div>
                    {selected.source_revision && (
                      <div className="sm:col-span-2">
                        <dt className="text-muted-foreground text-xs">진단한 소스 버전</dt>
                        <dd className="mt-1 break-all font-mono text-xs">{selected.source_revision}</dd>
                      </div>
                    )}
                    {selected.target_snapshot?.sha256 && (
                      <div className="sm:col-span-2">
                        <dt className="text-muted-foreground text-xs">진단에 사용한 등록 자료 SHA-256</dt>
                        <dd className="mt-1 break-all font-mono text-xs">{selected.target_snapshot.sha256}</dd>
                      </div>
                    )}
                  </dl>
                  {selectedDiscoveredApi && (
                    <details className="rounded-md border p-3">
                      <summary className="cursor-pointer text-sm">API 탐색 범위 · 한계</summary>
                      <div className="mt-2">
                        <DiscoveryDetails discovery={selected.target_snapshot?.discovery} />
                      </div>
                    </details>
                  )}
                  {!!selected.operation_ids?.length && (
                    <details className="rounded-md border p-3">
                      <summary className="cursor-pointer text-sm">
                        실행한 API 요청 범위 · {selected.operation_ids.length}개
                      </summary>
                      <ul className="mt-2 space-y-1 break-all font-mono text-muted-foreground text-xs">
                        {selected.operation_ids.map((id) => {
                          const operation = selected.target_snapshot?.operations?.find((item) => item.id === id);
                          return (
                            <li key={id}>{operation ? `${operation.method.toUpperCase()} ${operation.path}` : id}</li>
                          );
                        })}
                      </ul>
                    </details>
                  )}
                  {selected.summary && <p className="whitespace-pre-wrap text-sm">{selected.summary}</p>}
                  {selected.error && (
                    <Alert variant="destructive">
                      <AlertDescription>{selected.error}</AlertDescription>
                    </Alert>
                  )}
                  {isActive(selected) && (
                    <p role="status" className="flex items-center gap-2 text-muted-foreground text-sm">
                      <LoaderCircleIcon className="size-4 animate-spin" />
                      도구를 실행 중입니다. 완료되면 결과가 자동으로 갱신됩니다.
                    </p>
                  )}
                  <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">
                    <p className="font-medium">도구 발견 후보 {candidates.length}건 · 아직 취약점 확정 전</p>
                    <p className="mt-1 text-muted-foreground text-xs">{candidateNotice(selected)}</p>
                  </div>
                  {candidates.length > 0 ? (
                    <div className="max-h-[680px] space-y-2 overflow-y-auto pr-1">
                      {candidates.map((candidate, index) => (
                        <details
                          key={candidate.id || `${candidate.rule_id}-${index}`}
                          className="rounded-lg border p-3"
                        >
                          <summary className="cursor-pointer font-medium text-sm">
                            <span className="mr-2 text-muted-foreground text-xs">{candidate.severity}</span>
                            {candidate.title}
                            {candidate.file && (
                              <span className="mt-1 block break-all font-mono font-normal text-muted-foreground text-xs">
                                {candidate.file}
                                {candidate.line ? `:${candidate.line}` : ""}
                              </span>
                            )}
                          </summary>
                          <div className="mt-3 space-y-2 text-sm">
                            <Badge variant="outline">검토 전 후보</Badge>
                            {candidate.rule_id && (
                              <p className="break-all text-muted-foreground text-xs">규칙: {candidate.rule_id}</p>
                            )}
                            <p className="whitespace-pre-wrap break-words">{candidate.message}</p>
                            {candidate.evidence != null && (
                              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                                {evidenceText(candidate.evidence)}
                              </pre>
                            )}
                          </div>
                        </details>
                      ))}
                    </div>
                  ) : (
                    selected.status === "completed" && (
                      <p className="text-muted-foreground text-sm">
                        이번 도구·규칙·실행 범위에서 후보를 찾지 못했습니다. 대상에 취약점이 없다는 의미는 아닙니다.
                      </p>
                    )
                  )}
                  {!!selected.limitations?.length && (
                    <details className="rounded-md border p-3" open>
                      <summary className="cursor-pointer font-medium text-sm">진단 범위 · 해석의 한계</summary>
                      <ul className="mt-2 list-disc space-y-1 pl-5 text-muted-foreground text-xs">
                        {[...new Set(selected.limitations)].map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </details>
                  )}
                  {artifacts.length > 0 && (
                    <div className="space-y-2">
                      <p className="font-medium text-sm">원본 결과 다운로드</p>
                      {artifacts.map((artifact) => (
                        <div
                          key={artifact.name}
                          className="flex flex-wrap items-start justify-between gap-2 rounded-md border p-3"
                        >
                          <div className="min-w-0 flex-1">
                            <p className="break-all text-sm">{artifact.name}</p>
                            {artifact.sha256 && (
                              <p className="mt-1 break-all font-mono text-[10px] text-muted-foreground">
                                SHA-256: {artifact.sha256}
                              </p>
                            )}
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={!!downloading}
                            onClick={() => void download(selected.id, artifact.name)}
                          >
                            {downloading === artifact.name ? (
                              <LoaderCircleIcon className="size-3 animate-spin" />
                            ) : (
                              <DownloadIcon className="size-3" />
                            )}{" "}
                            다운로드
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">3. ARTEX 심층 검토</CardTitle>
                  <CardDescription>
                    기존 Planner·Worker가 진단 Skill과 수집한 근거를 바탕으로 후보를 검토합니다.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {selected.task_id ? (
                    <div className="space-y-3">
                      <p className="text-sm">
                        ARTEX 검토 작업이 연결되었습니다. 진행 과정과 최종 판정은 작업 화면에서 확인하세요.
                      </p>
                      <Button asChild>
                        <Link href={`/function/tasks/detail?id=${encodeURIComponent(selected.task_id)}`}>
                          ARTEX 검토 작업 열기 <ArrowUpRightIcon className="size-4" />
                        </Link>
                      </Button>
                    </div>
                  ) : (
                    <>
                      <div className="max-w-lg space-y-2">
                        <Label htmlFor={profileSelectId}>검토 모델</Label>
                        <select
                          id={profileSelectId}
                          value={profileId}
                          onChange={(event) => setProfileId(event.target.value)}
                          disabled={reviewing}
                          className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                        >
                          <option value="">시스템 기본 LLM 설정</option>
                          {profiles.map((profile) => (
                            <option key={profile.id} value={profile.id}>
                              {profile.name} · {profile.model}
                              {profile.is_default ? " (기본)" : ""}
                            </option>
                          ))}
                        </select>
                        <Link
                          href="/system/llm/"
                          className="inline-block text-primary text-xs underline underline-offset-4"
                        >
                          LLM 연결 설정
                        </Link>
                      </div>
                      <p className="text-muted-foreground text-xs">
                        AI 검토를 시작하면 진단 근거와 필요한 소스·응답 내용이 선택한 LLM으로 전송되며 모델 사용량이
                        발생합니다.
                      </p>
                      <Button disabled={selected.status !== "completed" || reviewing} onClick={() => void review()}>
                        {reviewing ? (
                          <LoaderCircleIcon className="size-4 animate-spin" />
                        ) : (
                          <FileSearchIcon className="size-4" />
                        )}
                        {reviewing ? "검토 작업 만드는 중…" : "ARTEX 심층 검토 시작"}
                      </Button>
                      {selected.status !== "completed" && (
                        <p className="text-muted-foreground text-xs">
                          도구 진단이 정상 완료된 실행에서 시작할 수 있습니다.
                        </p>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

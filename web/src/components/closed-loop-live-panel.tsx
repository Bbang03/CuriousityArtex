"use client";

import * as React from "react";

import Link from "next/link";

import {
  DownloadIcon,
  FileSearchIcon,
  PlayIcon,
  RefreshCwIcon,
  Repeat2Icon,
  SaveIcon,
  SearchIcon,
  SquareIcon,
  WandSparklesIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";

import { FindingDefenseFileUpload } from "@/components/finding-defense-file-upload";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api, HttpError } from "@/lib/api";
import type { LoopRule } from "@/lib/closedloop-api";
import {
  type LiveCycle,
  type LiveCycleObservation,
  type LiveCycleSummary,
  liveLoopApi,
} from "@/lib/closedloop-live-api";
import { type FindingDefense, purpleApi } from "@/lib/purple-api";
import {
  type DefenseExecution,
  type DefenseFileConfig,
  downloadSecurityJSON,
  type SecuritySource,
  securityApi,
} from "@/lib/security-api";
import type { Finding } from "@/lib/types";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50";
const fileDefaults: DefenseFileConfig = {
  label: "",
  timestamp_field: "timestamp",
  correlation_field: "artex_verification_id",
  action_field: "action",
  event_id_field: "id",
};
const json = (value: unknown) => JSON.stringify(value, null, 2);
const running = (execution?: DefenseExecution) =>
  execution?.retest.status === "pending" || execution?.retest.status === "running";

function requestUUID() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function ClosedLoopLivePanel() {
  const t = useTranslations("LiveLoop");
  const tu = useTranslations("purple.upload");
  const [records, setRecords] = React.useState<LiveCycleSummary[]>([]);
  const [selected, setSelected] = React.useState<LiveCycle | null>(null);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [findingQuery, setFindingQuery] = React.useState("");
  const [findingId, setFindingId] = React.useState("");
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [defense, setDefense] = React.useState<FindingDefense | null>(null);
  const [sources, setSources] = React.useState<SecuritySource[]>([]);
  const [sourceKind, setSourceKind] = React.useState<"file" | "splunk">("file");
  const [sourceId, setSourceId] = React.useState("");
  const [fileConfig, setFileConfig] = React.useState<DefenseFileConfig>({ ...fileDefaults });
  const [scenario, setScenario] = React.useState("");
  const [notes, setNotes] = React.useState("");
  const [logTarget, setLogTarget] = React.useState("");
  const [logPath, setLogPath] = React.useState("");
  const [baselineText, setBaselineText] = React.useState("");
  const [candidateText, setCandidateText] = React.useState("");
  const [candidateNote, setCandidateNote] = React.useState("");
  const [candidateDirty, setCandidateDirty] = React.useState(false);
  const [scopeConfirmed, setScopeConfirmed] = React.useState(false);
  const [busy, setBusy] = React.useState<string | null>("load");
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [suggestionWarnings, setSuggestionWarnings] = React.useState<string[]>([]);
  const [createOpen, setCreateOpen] = React.useState(true);
  const [uploadBusy, setUploadBusy] = React.useState(false);
  const seq = React.useRef(0);
  const findingSeq = React.useRef(0);
  const selectedRef = React.useRef<string | null>(null);
  const pendingCreate = React.useRef<{ key: string; requestId: string } | null>(null);
  const readySources = sources.filter((source) => source.enabled && source.credential_set);
  const sourceReady =
    sourceKind === "file"
      ? Object.values(fileConfig).every((value) => value.trim())
      : readySources.some((source) => source.id === sourceId);
  const activeExecution = selected?.current ?? selected?.baseline;
  const active = running(activeExecution);
  const baselineExecutionId = selected?.baseline.id;
  const baselineObservation = (selected?.observations ?? []).find(
    (item) => item.execution_id === baselineExecutionId && item.phase === "baseline",
  );
  const hasCandidate = Boolean(selected?.candidate_rule);
  const pairLocked = Boolean(selected?.current);

  const adopt = React.useCallback((cycle: LiveCycle, resetCandidate = false) => {
    selectedRef.current = cycle.id;
    setSelected(cycle);
    setRecords((rows) => [cycle, ...rows.filter((row) => row.id !== cycle.id)]);
    if (resetCandidate) {
      setCandidateText(cycle.candidate_rule ? json(cycle.candidate_rule) : "");
      setCandidateDirty(false);
      setCandidateNote("");
      setSuggestionWarnings([]);
    }
  }, []);
  const load = React.useCallback(async () => {
    const request = ++seq.current;
    setBusy("load");
    setError("");
    const results = await Promise.allSettled([
      liveLoopApi.list(),
      api.findingsPage({ page: 1, pageSize: 50 }),
      securityApi.sources(),
    ]);
    if (request !== seq.current) return;
    if (results[0].status === "fulfilled") setRecords(results[0].value.cycles ?? []);
    else setError((results[0].reason as Error).message);
    if (results[1].status === "fulfilled") setFindings(results[1].value.items ?? []);
    else setError((results[1].reason as Error).message);
    if (results[2].status === "fulfilled") setSources(results[2].value.sources ?? []);
    else setError((results[2].reason as Error).message);
    setBusy(null);
  }, []);
  React.useEffect(() => {
    void load();
    return () => {
      seq.current++;
      findingSeq.current++;
    };
  }, [load]);
  React.useEffect(() => {
    if (!findingId) {
      setFinding(null);
      setDefense(null);
      return;
    }
    const request = ++findingSeq.current;
    setFinding(null);
    setDefense(null);
    setError("");
    setScopeConfirmed(false);
    Promise.all([api.getFinding(findingId), purpleApi.findingDefense(findingId)])
      .then(([found, prepared]) => {
        if (request !== findingSeq.current) return;
        setFinding(found);
        setDefense(prepared);
        if (prepared.plan?.rule_format === "event_filter") {
          try {
            const rule = JSON.parse(prepared.plan.rule_text) as LoopRule;
            if (rule.any) setBaselineText(json(rule));
          } catch {
            setBaselineText("");
          }
        } else setBaselineText("");
      })
      .catch((caught: Error) => {
        if (request === findingSeq.current) setError(caught.message);
      });
    return () => {
      findingSeq.current++;
    };
  }, [findingId]);
  const selectedCycleId = selected?.id;
  React.useEffect(() => {
    if (!selectedCycleId || !active || busy || uploadBusy) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const cycle = await liveLoopApi.get(selectedCycleId);
        if (disposed || selectedRef.current !== cycle.id) return;
        adopt(cycle);
        setError("");
        if (running(cycle.current ?? cycle.baseline)) timer = setTimeout(() => void poll(), 3000);
      } catch (caught) {
        if (!disposed) {
          setError((caught as Error).message);
          timer = setTimeout(() => void poll(), 5000);
        }
      }
    };
    timer = setTimeout(() => void poll(), 2000);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [selectedCycleId, active, busy, uploadBusy, adopt]);
  const action = async (kind: string, work: () => Promise<void>) => {
    if (busy || uploadBusy) return;
    setBusy(kind);
    setError("");
    setNotice("");
    try {
      await work();
    } catch (caught) {
      if (caught instanceof HttpError && caught.status === 409 && selectedRef.current) {
        try {
          adopt(await liveLoopApi.get(selectedRef.current));
        } catch {
          /* Keep last confirmed record. */
        }
      }
      setError((caught as Error).message);
    } finally {
      setBusy(null);
    }
  };
  const create = async () => {
    if (!defense?.plan || !sourceReady || !scopeConfirmed || !finding || finding.inherited) return;
    const plan = defense.plan;
    await action("create", async () => {
      const rule = JSON.parse(baselineText) as LoopRule;
      const createKey = JSON.stringify({
        scenario,
        findingId,
        notes,
        rule,
        logTarget,
        logPath,
        sourceKind,
        sourceId,
        fileConfig,
        defense,
      });
      if (pendingCreate.current?.key !== createKey)
        pendingCreate.current = { key: createKey, requestId: requestUUID() };
      const response = await liveLoopApi.create({
        request_id: pendingCreate.current.requestId,
        scenario: scenario.trim(),
        finding_id: findingId,
        notes: notes.trim(),
        baseline_rule: rule,
        log_target: logTarget.trim(),
        log_path: logPath.trim(),
        defense: {
          source_kind: sourceKind,
          source_id: sourceKind === "file" ? "0" : sourceId,
          ...(sourceKind === "file" ? { file_config: fileConfig } : {}),
          plan_revision: plan.revision,
          expected_evidence_version: defense.evidence_version,
          expected_source_fingerprint: defense.source_fingerprint,
          remediation_note: "",
        },
      });
      adopt(response.cycle, true);
      pendingCreate.current = null;
      setCreateOpen(false);
      setNotice(t("started"));
    });
  };
  const open = async (id: string) =>
    action("open", async () => {
      adopt(await liveLoopApi.get(id), true);
      setCreateOpen(false);
    });
  const refreshSelected = async () => {
    if (selectedRef.current) adopt(await liveLoopApi.get(selectedRef.current));
  };
  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <Badge variant="outline">{t("liveBadge")}</Badge>
          <h1 className="font-semibold text-2xl tracking-tight">{t("title")}</h1>
          <p className="max-w-4xl text-muted-foreground text-sm leading-relaxed">{t("description")}</p>
        </div>
        <Button size="sm" variant="outline" disabled={!!busy || uploadBusy} onClick={() => void load()}>
          <RefreshCwIcon className={busy === "load" ? "animate-spin" : ""} />
          {t("refresh")}
        </Button>
      </div>
      <Alert>
        <AlertDescription>{t("boundary")}</AlertDescription>
      </Alert>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {notice ? (
        <Alert>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle>{t("prepare")}</CardTitle>
            <CardDescription>{t("prepareHelp")}</CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setCreateOpen((value) => !value)}>
            {t(createOpen ? "collapse" : "newCycle")}
          </Button>
        </CardHeader>
        {createOpen ? (
          <CardContent>
            <fieldset disabled={!!busy || uploadBusy} className="space-y-5">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="live-scenario">{t("scenario")}</Label>
                  <Input
                    id="live-scenario"
                    value={scenario}
                    onChange={(event) => setScenario(event.target.value)}
                    maxLength={200}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="live-finding">{t("finding")}</Label>
                  <select
                    id="live-finding"
                    className={SELECT_CLASS}
                    value={findingId}
                    onChange={(event) => setFindingId(event.target.value)}
                  >
                    <option value="">{t("chooseFinding")}</option>
                    {findings.map((item) => (
                      <option key={item.id} value={item.finding_id ?? item.id} disabled={item.inherited}>
                        {item.name || item.vulnclass} · #{item.finding_id ?? item.id}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Input
                  className="w-full sm:w-80"
                  aria-label={t("findingSearch")}
                  placeholder={t("findingSearch")}
                  value={findingQuery}
                  onChange={(event) => setFindingQuery(event.target.value)}
                />
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    void action("find", async () => {
                      const result = await api.findingsPage({ page: 1, pageSize: 50, query: findingQuery });
                      setFindings(result.items ?? []);
                    })
                  }
                >
                  <SearchIcon />
                  {t("search")}
                </Button>
                <Button size="sm" variant="ghost" asChild>
                  <Link href="/function/findings/">{t("allFindings")}</Link>
                </Button>
              </div>
              {finding && defense ? (
                <div className="space-y-2 rounded-lg border bg-muted/30 p-4">
                  <p className="font-medium text-sm">{finding.name || finding.vulnclass}</p>
                  <p className="whitespace-pre-wrap text-muted-foreground text-sm">{finding.summary}</p>
                  <p className="break-all text-xs">
                    {t("targets")}: {(finding.assets ?? []).map((asset) => asset.label).join(", ") || t("unknown")}
                  </p>
                  {defense.plan ? (
                    <>
                      <p className="text-xs">
                        {t("versions", { plan: defense.plan.revision, evidence: defense.evidence_version })}
                      </p>
                      <code className="block break-all text-muted-foreground text-xs">
                        {defense.source_fingerprint}
                      </code>
                    </>
                  ) : (
                    <Alert>
                      <AlertDescription>{t("planRequired")}</AlertDescription>
                    </Alert>
                  )}
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" asChild>
                      <Link href={`/function/findings/detail/?id=${encodeURIComponent(findingId)}&tab=defense`}>
                        {t("openPlan")}
                      </Link>
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        void action("plan", async () => {
                          const latest = await purpleApi.findingDefense(findingId);
                          setDefense(latest);
                          setScopeConfirmed(false);
                          if (latest.plan?.rule_format === "event_filter") {
                            try {
                              const rule = JSON.parse(latest.plan.rule_text) as LoopRule;
                              if (rule.any) setBaselineText(json(rule));
                            } catch {
                              /* Keep the user's rule draft. */
                            }
                          }
                        })
                      }
                    >
                      <RefreshCwIcon />
                      {t("refreshPlan")}
                    </Button>
                  </div>
                </div>
              ) : null}
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="live-source-kind">{t("source")}</Label>
                  <select
                    id="live-source-kind"
                    className={SELECT_CLASS}
                    value={sourceKind}
                    onChange={(event) => setSourceKind(event.target.value as "file" | "splunk")}
                  >
                    <option value="file">{t("file")}</option>
                    <option value="splunk">Splunk</option>
                  </select>
                </div>
                {sourceKind === "splunk" ? (
                  <div className="space-y-2">
                    <Label htmlFor="live-source">{t("sourceConnection")}</Label>
                    <select
                      id="live-source"
                      className={SELECT_CLASS}
                      value={sourceId}
                      onChange={(event) => setSourceId(event.target.value)}
                    >
                      <option value="">{t("chooseSource")}</option>
                      {readySources.map((source) => (
                        <option key={source.id} value={source.id}>
                          {source.name} · r{source.revision}
                        </option>
                      ))}
                    </select>
                    <Link href="/function/purple/sources/" className="text-xs underline">
                      {t("manageSources")}
                    </Link>
                    {!readySources.length ? <p className="text-muted-foreground text-sm">{t("noSources")}</p> : null}
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Label htmlFor="live-file-label">{t("fileLabel")}</Label>
                    <Input
                      id="live-file-label"
                      value={fileConfig.label}
                      onChange={(event) => setFileConfig((value) => ({ ...value, label: event.target.value }))}
                      maxLength={120}
                    />
                  </div>
                )}
              </div>
              {sourceKind === "file" ? (
                <details className="rounded-lg border p-4">
                  <summary className="cursor-pointer font-medium text-sm">{t("fileMapping")}</summary>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    {(["timestamp_field", "correlation_field", "action_field", "event_id_field"] as const).map(
                      (key) => (
                        <div key={key} className="space-y-2">
                          <Label htmlFor={`live-${key}`}>{tu(key)}</Label>
                          <Input
                            id={`live-${key}`}
                            value={fileConfig[key]}
                            onChange={(event) => setFileConfig((value) => ({ ...value, [key]: event.target.value }))}
                            maxLength={128}
                          />
                        </div>
                      ),
                    )}
                  </div>
                </details>
              ) : null}
              <details className="rounded-lg border p-4">
                <summary className="cursor-pointer font-medium text-sm">{t("logScope")}</summary>
                <p className="mt-2 text-muted-foreground text-xs">{t("logScopeHelp")}</p>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="live-log-target">{t("logTarget")}</Label>
                    <Input
                      id="live-log-target"
                      value={logTarget}
                      onChange={(event) => setLogTarget(event.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="live-log-path">{t("logPath")}</Label>
                    <Input id="live-log-path" value={logPath} onChange={(event) => setLogPath(event.target.value)} />
                  </div>
                </div>
              </details>
              <div className="space-y-2">
                <Label htmlFor="live-baseline-rule">{t("baselineRule")}</Label>
                <Textarea
                  id="live-baseline-rule"
                  value={baselineText}
                  onChange={(event) => setBaselineText(event.target.value)}
                  rows={7}
                  className="font-mono text-xs"
                  placeholder={t("rulePlaceholder")}
                />
                <p className="text-muted-foreground text-xs">{t("ruleHelp")}</p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="live-notes">{t("notes")}</Label>
                <Textarea
                  id="live-notes"
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                  rows={2}
                  maxLength={4000}
                />
              </div>
              <div className="flex items-start gap-2">
                <Checkbox
                  id="live-scope-confirmed"
                  checked={scopeConfirmed}
                  onCheckedChange={(value) => setScopeConfirmed(value === true)}
                />
                <Label htmlFor="live-scope-confirmed" className="text-sm leading-relaxed">
                  {t("scopeConfirmed")}
                </Label>
              </div>
              <Button
                disabled={
                  !scenario.trim() ||
                  !finding ||
                  !defense?.plan ||
                  !sourceReady ||
                  !baselineText.trim() ||
                  !scopeConfirmed ||
                  finding.inherited
                }
                onClick={() => void create()}
              >
                {busy === "create" ? <Spinner /> : <PlayIcon />}
                {t("startBaseline")}
              </Button>
              <p className="text-muted-foreground text-xs">{t("llmDisclosure")}</p>
            </fieldset>
          </CardContent>
        ) : null}
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("history")}</CardTitle>
          <CardDescription>{t("historyHelp")}</CardDescription>
        </CardHeader>
        <CardContent>
          {busy === "load" && !records.length ? (
            <Skeleton className="h-20 w-full" />
          ) : !records.length ? (
            <p className="text-muted-foreground text-sm">{t("emptyHistory")}</p>
          ) : (
            <div className="grid gap-3 lg:grid-cols-2">
              {records.map((record) => (
                <button
                  key={record.id}
                  type="button"
                  disabled={!!busy || uploadBusy}
                  onClick={() => void open(record.id)}
                  className={`space-y-2 rounded-lg border p-4 text-left transition-colors hover:bg-muted/50 disabled:opacity-50 ${selected?.id === record.id ? "border-violet-500/50 bg-violet-500/5" : ""}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-sm">{record.scenario}</span>
                    <Badge variant="secondary">{t(`status.${record.status}`)}</Badge>
                  </div>
                  <p className="text-muted-foreground text-xs">
                    #{record.id} · {t("revision", { n: record.revision })} ·{" "}
                    {new Date(record.created_at).toLocaleString()}
                  </p>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      {selected ? (
        <>
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
              <div className="space-y-1.5">
                <CardTitle>{selected.scenario}</CardTitle>
                <CardDescription>
                  #{selected.id} · {t("revision", { n: selected.revision })}
                </CardDescription>
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!!busy || uploadBusy}
                  onClick={() => void action("refresh", refreshSelected)}
                >
                  <RefreshCwIcon />
                  {t("refresh")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!!busy || uploadBusy}
                  onClick={() =>
                    void action("export", async () =>
                      downloadSecurityJSON(
                        await liveLoopApi.export(selected.id),
                        `aegisloop-live-cycle-${selected.id}.json`,
                      ),
                    )
                  }
                >
                  <DownloadIcon />
                  {t("export")}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={active ? "default" : "secondary"}>
                  {active ? <Spinner /> : null}
                  {t(`status.${selected.status}`)}
                </Badge>
                <Button variant="ghost" size="sm" asChild>
                  <Link
                    href={`/function/findings/detail/?id=${encodeURIComponent(selected.finding_id)}&tab=investigation`}
                  >
                    <FileSearchIcon />
                    {t("investigate")}
                  </Link>
                </Button>
              </div>
              <div className="grid gap-4 lg:grid-cols-2">
                <LiveExecutionView execution={selected.baseline} phase="baseline" />
                {selected.current ? (
                  <LiveExecutionView execution={selected.current} phase="rerun" />
                ) : (
                  <div className="flex items-center justify-center rounded-lg border border-dashed p-6 text-muted-foreground text-sm">
                    {t("rerunPending")}
                  </div>
                )}
              </div>
              {active && activeExecution ? (
                <div className="flex flex-wrap items-center gap-3">
                  <Button
                    variant="outline"
                    disabled={!!busy || uploadBusy}
                    onClick={() => void action("stop", async () => adopt(await liveLoopApi.stop(selected.id)))}
                  >
                    {busy === "stop" ? <Spinner /> : <SquareIcon />}
                    {t("stop")}
                  </Button>
                  <p className="text-muted-foreground text-xs">{t("runningHelp")}</p>
                </div>
              ) : null}
              <div className="space-y-2 rounded-lg bg-muted/30 p-4">
                <p className="font-medium text-sm">{t("correlation")}</p>
                <p className="text-muted-foreground text-xs">{t("correlationHelp")}</p>
                <code className="block break-all text-xs">{activeExecution?.correlation_id}</code>
                <p className="text-muted-foreground text-xs">
                  {t("autoScope")}: {selected.log_target}
                  {selected.log_path}
                </p>
              </div>
              {!active && activeExecution ? (
                <div className="space-y-4">
                  {activeExecution.source_kind === "file" ? (
                    <FindingDefenseFileUpload
                      key={activeExecution.id}
                      findingId={selected.finding_id}
                      execution={activeExecution}
                      disabled={!!busy || uploadBusy}
                      readOnly={false}
                      onRunningChange={setUploadBusy}
                      onUploaded={async () => {
                        adopt(await liveLoopApi.collect(selected.id));
                      }}
                    />
                  ) : null}
                  <div className="flex flex-wrap gap-3">
                    <Button
                      disabled={!!busy || uploadBusy}
                      onClick={() =>
                        void action("collect", async () => {
                          adopt(await liveLoopApi.collect(selected.id));
                          setNotice(t("collected"));
                        })
                      }
                    >
                      {busy === "collect" ? <Spinner /> : <SearchIcon />}
                      {t(activeExecution.source_kind === "file" ? "evaluateUploaded" : "collect")}
                    </Button>
                    <p className="self-center text-muted-foreground text-xs">{t("collectionHelp")}</p>
                  </div>
                </div>
              ) : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{t("candidateTitle")}</CardTitle>
              <CardDescription>{t("candidateHelp")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button
                variant="outline"
                disabled={!!busy || uploadBusy || active || pairLocked || !baselineObservation}
                onClick={() =>
                  void action("suggest", async () => {
                    const proposal = await liveLoopApi.suggest(selected.id);
                    setCandidateText(json(proposal.candidate_rule));
                    setCandidateDirty(true);
                    setSuggestionWarnings(proposal.warnings ?? []);
                    setNotice(t("suggested"));
                  })
                }
              >
                {busy === "suggest" ? <Spinner /> : <WandSparklesIcon />}
                {t("suggest")}
              </Button>
              <div className="grid gap-4 xl:grid-cols-2">
                <div className="space-y-2">
                  <h3 className="font-medium text-sm">{t("savedBaseline")}</h3>
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/20 p-3 text-xs">
                    {json(selected.baseline_rule)}
                  </pre>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="live-candidate">{t("candidateRule")}</Label>
                  <Textarea
                    id="live-candidate"
                    className="font-mono text-xs"
                    rows={10}
                    value={candidateText}
                    disabled={!!busy || uploadBusy || active || pairLocked}
                    onChange={(event) => {
                      setCandidateText(event.target.value);
                      setCandidateDirty(true);
                    }}
                    placeholder={t("rulePlaceholder")}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="live-candidate-note">{t("candidateNote")}</Label>
                <Textarea
                  id="live-candidate-note"
                  value={candidateNote}
                  onChange={(event) => setCandidateNote(event.target.value)}
                  rows={2}
                  maxLength={4000}
                  disabled={!!busy || uploadBusy || active || pairLocked}
                />
              </div>
              {selected.remediation_note ? (
                <p className="whitespace-pre-wrap text-muted-foreground text-sm">
                  {t("candidateNote")}: {selected.remediation_note}
                </p>
              ) : null}
              {suggestionWarnings.length ? (
                <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-sm">
                  {suggestionWarnings.map((warning) => (
                    <li key={warning}>{t.has(`warnings.${warning}`) ? t(`warnings.${warning}`) : warning}</li>
                  ))}
                </ul>
              ) : null}
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  disabled={
                    !!busy ||
                    uploadBusy ||
                    active ||
                    pairLocked ||
                    !baselineObservation ||
                    !candidateText.trim() ||
                    !candidateNote.trim() ||
                    !candidateDirty
                  }
                  onClick={() =>
                    void action("candidate", async () => {
                      const cycle = await liveLoopApi.saveCandidate(selected.id, {
                        expected_revision: selected.revision,
                        rule: JSON.parse(candidateText) as LoopRule,
                        note: candidateNote.trim(),
                      });
                      adopt(cycle, true);
                      setNotice(t("candidateSaved"));
                    })
                  }
                >
                  {busy === "candidate" ? <Spinner /> : <SaveIcon />}
                  {t("saveCandidate")}
                </Button>
                <Button
                  variant="outline"
                  disabled={!!busy || uploadBusy || active || pairLocked || !hasCandidate || candidateDirty}
                  onClick={() =>
                    void action("rerun", async () => {
                      const response = await liveLoopApi.rerun(selected.id, selected.revision);
                      adopt(response.cycle);
                      setNotice(t("rerunStarted"));
                    })
                  }
                >
                  {busy === "rerun" ? <Spinner /> : <Repeat2Icon />}
                  {t("startRerun")}
                </Button>
              </div>
              {candidateDirty ? (
                <p className="text-amber-700 text-sm dark:text-amber-300">{t("candidateDirty")}</p>
              ) : null}
              {pairLocked ? <p className="text-muted-foreground text-sm">{t("pairLocked")}</p> : null}
              <p className="text-muted-foreground text-xs leading-relaxed">{t("shadowBoundary")}</p>
            </CardContent>
          </Card>
          {(selected.observations ?? []).length ? (
            <Card>
              <CardHeader>
                <CardTitle>{t("evidenceTitle")}</CardTitle>
                <CardDescription>{t("evidenceHelp")}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                {(selected.observations ?? []).map((observation) => (
                  <LiveObservationView key={observation.id} observation={observation} />
                ))}
              </CardContent>
            </Card>
          ) : null}
          <Card>
            <CardHeader>
              <CardTitle>{t("comparison")}</CardTitle>
              <CardDescription>{t("comparisonHelp")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("resultKind")}</TableHead>
                    <TableHead>{t("baselinePhase")}</TableHead>
                    <TableHead>{t("rerunPhase")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell>{t("nativeDetection")}</TableCell>
                    <TableCell>{verdictLabel(selected.comparison.baseline_native_detection, t)}</TableCell>
                    <TableCell>{verdictLabel(selected.comparison.current_native_detection, t)}</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
              <div className="space-y-2 rounded-lg border p-4">
                <p className="font-medium text-sm">{t("candidateNativeTitle")}</p>
                <Badge
                  variant={selected.comparison.candidate_native_rule_detection === "detected" ? "default" : "secondary"}
                >
                  {t(
                    selected.comparison.candidate_native_rule_detection === "detected"
                      ? "candidateNativeDetected"
                      : "candidateNativeNotAttributed",
                  )}
                </Badge>
                <p className="text-muted-foreground text-xs leading-relaxed">{t("candidateNativeHelp")}</p>
              </div>
              <div className="space-y-2">
                <p className="font-medium text-sm">{t("sameRerunAudits")}</p>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("resultKind")}</TableHead>
                      <TableHead>{t("baselineRule")}</TableHead>
                      <TableHead>{t("candidateRule")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    <TableRow>
                      <TableCell>{t("shadowDetection")}</TableCell>
                      <TableCell>{verdictLabel(selected.comparison.baseline_shadow_detection, t)}</TableCell>
                      <TableCell>{verdictLabel(selected.comparison.candidate_shadow_detection, t)}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </div>
              <Badge variant={selected.comparison.comparable ? "default" : "secondary"}>
                {t(selected.comparison.comparable ? "comparable" : "notComparable")}
              </Badge>
              {(selected.comparison.reasons ?? []).length ? (
                <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-sm">
                  {(selected.comparison.reasons ?? []).map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : null}
              <p className="text-muted-foreground text-xs leading-relaxed">{t("metricBoundary")}</p>
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}
function verdictLabel(value: string | undefined, t: ReturnType<typeof useTranslations>) {
  if (!value) return t("notCollected");
  return t.has(`verdict.${value}`) ? t(`verdict.${value}`) : value;
}
function LiveExecutionView({ execution, phase }: { execution: DefenseExecution; phase: "baseline" | "rerun" }) {
  const t = useTranslations("LiveLoop");
  const tr = useTranslations("retest.panel");
  return (
    <div className="space-y-3 rounded-lg border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-medium">{t(phase === "baseline" ? "baselinePhase" : "rerunPhase")}</h3>
        <Badge variant={running(execution) ? "default" : "secondary"}>{tr(`status.${execution.retest.status}`)}</Badge>
      </div>
      <p className="break-all text-muted-foreground text-xs">
        {t("executionId")}: {execution.id} · {t("retestId")}: {execution.retest.id}
      </p>
      <code className="block break-all text-xs">{execution.correlation_id}</code>
      <p className="text-sm">
        {t("reproduction")}: {execution.retest.verdict ? tr(`verdict.${execution.retest.verdict}`) : t("pending")}
      </p>
      {execution.retest.summary ? (
        <p className="whitespace-pre-wrap text-muted-foreground text-sm leading-relaxed">{execution.retest.summary}</p>
      ) : null}
      {execution.retest.error ? (
        <Alert variant="destructive">
          <AlertDescription>{execution.retest.error}</AlertDescription>
        </Alert>
      ) : null}
      <p className="text-muted-foreground text-xs">
        {execution.retest.started_at ? new Date(execution.retest.started_at).toLocaleString() : "—"} →{" "}
        {execution.retest.finished_at ? new Date(execution.retest.finished_at).toLocaleString() : "—"}
      </p>
      {execution.retest.conversation_id ? (
        <Button variant="ghost" size="sm" asChild>
          <Link href={`/chat/?c=${execution.retest.conversation_id}`}>{t("attackTrace")}</Link>
        </Button>
      ) : null}
    </div>
  );
}
function LiveObservationView({ observation }: { observation: LiveCycleObservation }) {
  const t = useTranslations("LiveLoop");
  const tp = useTranslations("purple.execution");
  return (
    <div className="space-y-3 rounded-lg border p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline">{t(observation.phase === "baseline" ? "baselinePhase" : "rerunPhase")}</Badge>
        <Badge variant="secondary">{t("revision", { n: observation.rule_revision })}</Badge>
        <span className="text-muted-foreground text-xs">{new Date(observation.created_at).toLocaleString()}</span>
      </div>
      <p className="break-all text-xs">
        {t("executionId")}: {observation.execution_id} · {t("assessmentId")}: {observation.assessment_id}
      </p>
      <div className="grid gap-3 md:grid-cols-2">
        <div className="space-y-2 rounded-md bg-muted/30 p-3">
          <p className="font-medium text-sm">{t("nativeTitle")}</p>
          <p className="text-sm">
            {tp("detectionTitle")}: {tp(`detection.${observation.native.detection}`)}
          </p>
          <p className="text-sm">
            {tp("preventionTitle")}: {tp(`prevention.${observation.native.prevention}`)}
          </p>
          <p className="text-muted-foreground text-xs">
            {t("nativeCounts", { audit: observation.native.audit_count, alert: observation.native.alert_count })}
          </p>
        </div>
        <div className="space-y-2 rounded-md bg-violet-500/5 p-3">
          <p className="font-medium text-sm">{t("shadowTitle")}</p>
          <Badge variant={observation.shadow.complete ? "outline" : "secondary"}>
            {t(observation.shadow.complete ? "complete" : "incomplete")}
          </Badge>
          <p className="text-muted-foreground text-xs">{t("shadowBoundary")}</p>
        </div>
      </div>
      {(observation.native.reasons ?? []).length ? (
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {observation.native.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
      {(observation.native.recommendations ?? []).length ? (
        <div className="space-y-2 rounded-md bg-muted/20 p-3">
          <p className="font-medium text-sm">{tp("recommendations")}</p>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-sm">
            {observation.native.recommendations.map((recommendation) => (
              <li key={recommendation}>{recommendation}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {observation.native_rule_refs?.length ? (
        <div className="space-y-2 rounded-md border p-3">
          <p className="font-medium text-sm">{t("nativeRuleRefs")}</p>
          {observation.native_rule_refs.map((ref) => (
            <p key={`${ref.detection_rule_id}:${ref.rule_sha256}`} className="break-all font-mono text-xs">
              {ref.detection_rule_id} · {ref.rule_sha256}
            </p>
          ))}
        </div>
      ) : null}
      <code className="block break-all text-muted-foreground text-xs">SHA-256: {observation.evidence_sha256}</code>
      <p className="text-muted-foreground text-xs">
        {t("actualWindow")}: {new Date(observation.shadow.window_start).toLocaleString()} →{" "}
        {new Date(observation.shadow.window_end).toLocaleString()}
      </p>
      <details className="rounded-md border p-3">
        <summary className="cursor-pointer font-medium text-sm">{t("ruleHashes")}</summary>
        <div className="mt-3 space-y-2 text-xs">
          <code className="block break-all">
            {t("baselineRule")}: {observation.shadow.baseline_rule_sha256}
          </code>
          <code className="block break-all">
            {t("candidateRule")}:{" "}
            {observation.phase === "rerun" ? observation.shadow.candidate_rule_sha256 : t("noCandidateRule")}
          </code>
        </div>
      </details>
      {observation.shadow.warnings?.length ? (
        <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-sm">
          {observation.shadow.warnings.map((warning) => (
            <li key={warning}>{t.has(`warnings.${warning}`) ? t(`warnings.${warning}`) : warning}</li>
          ))}
        </ul>
      ) : null}
      <details className="rounded-md border p-3">
        <summary className="cursor-pointer font-medium text-sm">{t("shadowEvents")}</summary>
        <div className="mt-3 max-h-80 overflow-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("eventId")}</TableHead>
                <TableHead>{t("baselineRule")}</TableHead>
                <TableHead>{t("candidateRule")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(observation.shadow.events ?? []).map((event) => (
                <TableRow key={event.event_id}>
                  <TableCell className="break-all font-mono text-xs">{event.event_id}</TableCell>
                  <TableCell>{verdictLabel(event.baseline, t)}</TableCell>
                  <TableCell>
                    {observation.phase === "rerun" ? verdictLabel(event.candidate, t) : t("noCandidateRule")}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </details>
      <details className="rounded-md border p-3">
        <summary className="cursor-pointer font-medium text-sm">{t("sourceQuery")}</summary>
        <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">
          {observation.shadow.query}
        </pre>
      </details>
    </div>
  );
}

"use client";

import * as React from "react";

import {
  CheckCircle2Icon,
  ChevronRightIcon,
  DownloadIcon,
  MonitorIcon,
  PlayIcon,
  RefreshCwIcon,
  Repeat2Icon,
  SaveIcon,
  SearchIcon,
  WandSparklesIcon,
  WorkflowIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";

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
import {
  type ChainRule,
  isChainRule,
  type RangeCase,
  type RangeCycle,
  type RangeEvidence,
  type RangeExplanation,
  type RangeMetrics,
  type RangeRule,
  type RangeRun,
  type RangeStatus,
  rangeLoopApi,
} from "@/lib/closedloop-range-api";
import { downloadSecurityJSON } from "@/lib/security-api";

const ACTIVE = new Set(["queued", "running", "rerunning", "collecting", "deploying"]);
const json = (value: unknown) => JSON.stringify(value, null, 2);
const time = (value?: string | null) => (value ? new Date(value).toLocaleString() : "—");

function requestUUID() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function ClosedLoopRangePanel() {
  const t = useTranslations("RangeLoop");
  const [status, setStatus] = React.useState<RangeStatus | null>(null);
  const [records, setRecords] = React.useState<RangeCycle[]>([]);
  const [recordsLoaded, setRecordsLoaded] = React.useState(false);
  const [selected, setSelected] = React.useState<RangeCycle | null>(null);
  const [name, setName] = React.useState("");
  const [scenarioIDs, setScenarioIDs] = React.useState<string[]>([]);
  const [candidateText, setCandidateText] = React.useState("");
  const [candidateNote, setCandidateNote] = React.useState("");
  const [candidateDirty, setCandidateDirty] = React.useState(false);
  const [warnings, setWarnings] = React.useState<string[]>([]);
  const [suggestionExplanation, setSuggestionExplanation] = React.useState<RangeExplanation | null>(null);
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [busy, setBusy] = React.useState<string | null>("load");
  const requestSeq = React.useRef(0);
  const selectedID = React.useRef<string | null>(null);
  const pendingCreate = React.useRef<{ key: string; id: string } | null>(null);
  const selectionInitialized = React.useRef(false);
  const ready = Boolean(status?.configured && status.ready);
  const active = Boolean(selected && ACTIVE.has(selected.status));
  const pairLocked = Boolean(selected?.current);
  const currentRun = selected?.current ?? selected?.baseline;
  const scenarios = status?.scenarios ?? [];
  const chain = selected?.kind === "scheduled_task_chain" || isChainRule(selected?.baseline_rule);
  const baselineReady =
    Boolean(selected?.baseline.evidence) &&
    (!chain ||
      Boolean(
        selected?.baseline.evidence?.complete &&
          selected.comparison.baseline_metrics &&
          selected.comparison.baseline_metrics.unknown === 0,
      ));
  let chainDraft: ChainRule | null = null;
  try {
    const draft = JSON.parse(candidateText) as RangeRule;
    if (isChainRule(draft)) chainDraft = draft;
  } catch {
    /* A draft is optional until the user reviews a candidate. */
  }

  React.useEffect(() => {
    if (!selectionInitialized.current && status?.scenarios?.some((scenario) => scenario.id === "ps_task_chain")) {
      selectionInitialized.current = true;
      setScenarioIDs(["ps_task_chain"]);
      setName((value) => value || t("chain.defaultName"));
    }
  }, [status?.scenarios, t]);
  const label = (value: string, rerun = false) =>
    value === "completed" && !rerun
      ? t("status.baseline_collected")
      : value === "running" && rerun
        ? t("status.rerunning")
        : t.has(`status.${value}`)
          ? t(`status.${value}`)
          : value;

  const adopt = React.useCallback((cycle: RangeCycle, resetDraft = false) => {
    const url = new URL(window.location.href);
    url.searchParams.set("tab", "range");
    url.searchParams.set("cycle", cycle.id);
    window.history.replaceState(null, "", url);
    selectedID.current = cycle.id;
    setSelected(cycle);
    setRecords((rows) => [cycle, ...rows.filter((row) => row.id !== cycle.id)]);
    if (resetDraft) {
      setCandidateText(cycle.candidate_rule ? json(cycle.candidate_rule) : "");
      setCandidateNote(cycle.candidate_note ?? "");
      setCandidateDirty(false);
      setWarnings([]);
      setSuggestionExplanation(cycle.candidate_explanation ?? null);
    }
  }, []);

  // A deployment can finish after the POST response. Preserve unsaved edits.
  const appliedCandidate = selected?.candidate_rule;
  React.useEffect(() => {
    if (!candidateDirty && appliedCandidate) setCandidateText(json(appliedCandidate));
  }, [appliedCandidate, candidateDirty]);
  React.useEffect(() => {
    if (!candidateDirty && selected?.candidate_explanation) setSuggestionExplanation(selected.candidate_explanation);
  }, [selected?.candidate_explanation, candidateDirty]);

  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    setBusy("load");
    setError("");
    const results = await Promise.allSettled([rangeLoopApi.status(), rangeLoopApi.list()]);
    if (seq !== requestSeq.current) return;
    if (results[0].status === "fulfilled") setStatus(results[0].value);
    else {
      setStatus(null);
      setError((results[0].reason as Error).message);
    }
    if (results[1].status === "fulfilled") {
      setRecords(results[1].value.cycles ?? []);
      setRecordsLoaded(true);
    } else {
      setRecordsLoaded(false);
      setError((results[1].reason as Error).message);
    }
    const requestedCycle = new URL(window.location.href).searchParams.get("cycle");
    if (requestedCycle) {
      try {
        const cycle = await rangeLoopApi.get(requestedCycle);
        if (seq !== requestSeq.current) return;
        adopt(cycle, selectedID.current !== cycle.id);
      } catch (caught) {
        if (seq !== requestSeq.current) return;
        setError(`${t("unknownCycle")} ${(caught as Error).message}`);
      }
    }
    setBusy(null);
  }, [adopt, t]);

  React.useEffect(() => {
    void load();
    return () => {
      requestSeq.current++;
    };
  }, [load]);

  const cycleID = selected?.id;
  React.useEffect(() => {
    if (!cycleID || !active || busy) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const cycle = await rangeLoopApi.get(cycleID);
        if (disposed || selectedID.current !== cycle.id) return;
        adopt(cycle);
        setError("");
        if (ACTIVE.has(cycle.status)) timer = setTimeout(() => void poll(), 3000);
      } catch (caught) {
        if (!disposed) {
          setError((caught as Error).message);
          timer = setTimeout(() => void poll(), 5000);
        }
      }
    };
    timer = setTimeout(() => void poll(), 3000);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [cycleID, active, busy, adopt]);

  const action = async (kind: string, work: () => Promise<void>) => {
    if (busy) return;
    setBusy(kind);
    setError("");
    setNotice("");
    try {
      await work();
    } catch (caught) {
      // A timeout may leave a durable asynchronous job. Read its actual state.
      if (selectedID.current) {
        try {
          adopt(await rangeLoopApi.get(selectedID.current));
        } catch {
          /* Preserve last confirmed state. */
        }
      }
      setError((caught as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const parseRule = () => {
    try {
      const rule = JSON.parse(candidateText) as RangeRule;
      if (!rule || typeof rule.name !== "string") throw new Error();
      if (isChainRule(rule)) {
        if (!["powershell_broad", "task_behavior"].includes(rule.profile)) throw new Error();
      } else if (!Array.isArray(rule.any) || !rule.any.length) throw new Error();
      return rule;
    } catch {
      throw new Error(t("invalidRule"));
    }
  };

  const create = () =>
    action("create", async () => {
      const input = { name: name.trim(), scenario_ids: [...scenarioIDs].sort() };
      const key = JSON.stringify(input);
      if (pendingCreate.current?.key !== key) pendingCreate.current = { key, id: requestUUID() };
      adopt(await rangeLoopApi.create({ ...input, request_id: pendingCreate.current.id }), true);
      pendingCreate.current = null;
      setNotice(t("started"));
    });

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <Badge variant="outline">
            <MonitorIcon className="mr-1 size-3" />
            {t("badge")}
          </Badge>
          <h1 className="font-semibold text-2xl tracking-tight">{t("title")}</h1>
          <p className="max-w-4xl text-muted-foreground text-sm leading-relaxed">{t("description")}</p>
        </div>
        <Button size="sm" variant="outline" disabled={!!busy} onClick={() => void load()}>
          {busy === "load" ? <Spinner /> : <RefreshCwIcon />}
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
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            {t("environment")}
            <Badge variant={ready ? "default" : "secondary"}>{t(ready ? "ready" : "notReady")}</Badge>
          </CardTitle>
          <CardDescription>{status?.message || t("connectionHelp")}</CardDescription>
        </CardHeader>
        <CardContent>
          {busy === "load" && !status ? (
            <Skeleton className="h-14 w-full" />
          ) : status?.environment ? (
            <dl className="grid gap-3 text-sm md:grid-cols-3">
              {(["name", "host", "telemetry_source"] as const).map((key) => (
                <div key={key} className="space-y-1 rounded-md bg-muted/30 p-3">
                  <dt className="text-muted-foreground text-xs">{t(`environmentFields.${key}`)}</dt>
                  <dd className="break-all font-medium">{status.environment?.[key] || "—"}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-muted-foreground text-sm">{t("connectionHelp")}</p>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t("prepare")}</CardTitle>
          <CardDescription>{t("prepareHelp")}</CardDescription>
        </CardHeader>
        <CardContent>
          <fieldset disabled={!!busy || active || !ready} className="space-y-4">
            <div className="max-w-xl space-y-2">
              <Label htmlFor="range-name">{t("cycleName")}</Label>
              <Input id="range-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} />
            </div>
            <div className="grid gap-3 lg:grid-cols-3">
              {scenarios.map((scenario) => (
                <div key={scenario.id} className="space-y-2 rounded-lg border p-4">
                  <div className="flex items-start gap-2">
                    <Checkbox
                      id={`range-scenario-${scenario.id}`}
                      checked={scenarioIDs.includes(scenario.id)}
                      onCheckedChange={(value) => {
                        selectionInitialized.current = true;
                        setScenarioIDs((ids) =>
                          value !== true
                            ? ids.filter((id) => id !== scenario.id)
                            : scenario.id === "ps_task_chain"
                              ? [scenario.id]
                              : [...ids.filter((id) => id !== scenario.id && id !== "ps_task_chain"), scenario.id],
                        );
                      }}
                    />
                    <Label htmlFor={`range-scenario-${scenario.id}`} className="font-medium leading-relaxed">
                      {scenario.name}
                    </Label>
                  </div>
                  <Badge variant="outline">{scenario.technique}</Badge>
                  {scenario.id === "ps_task_chain" ? <Badge>{t("chain.recommended")}</Badge> : null}
                  <p className="text-muted-foreground text-sm leading-relaxed">{scenario.description}</p>
                </div>
              ))}
            </div>
            {!scenarios.length ? <p className="text-muted-foreground text-sm">{t("noScenarios")}</p> : null}
            {scenarioIDs.includes("ps_task_chain") ? (
              <Alert>
                <AlertDescription>{t("chain.packHelp")}</AlertDescription>
              </Alert>
            ) : null}
            <Button
              disabled={
                !name.trim() || !scenarioIDs.length || !scenarioIDs.every((id) => scenarios.some((s) => s.id === id))
              }
              onClick={() => void create()}
            >
              {busy === "create" ? <Spinner /> : <PlayIcon />}
              {t("startBaseline")}
            </Button>
            <p className="text-muted-foreground text-xs leading-relaxed">{t("baselineDeployment")}</p>
          </fieldset>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("history")}</CardTitle>
          <CardDescription>{t("historyHelp")}</CardDescription>
        </CardHeader>
        <CardContent>
          {!records.length ? (
            <p className="text-muted-foreground text-sm">{t(recordsLoaded ? "emptyHistory" : "historyUnavailable")}</p>
          ) : (
            <div className="grid gap-3 lg:grid-cols-2">
              {records.map((record) => (
                <button
                  key={record.id}
                  type="button"
                  disabled={!!busy}
                  onClick={() => void action("open", async () => adopt(await rangeLoopApi.get(record.id), true))}
                  className={`space-y-2 rounded-lg border p-4 text-left transition-colors hover:bg-muted/50 disabled:opacity-50 ${selected?.id === record.id ? "border-sky-500/50 bg-sky-500/5" : ""}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-sm">{record.name}</span>
                    <Badge variant="secondary">{label(record.status, Boolean(record.current))}</Badge>
                  </div>
                  <p className="break-all text-muted-foreground text-xs">
                    {record.id} · {t("revision", { n: record.revision })} · {time(record.created_at)}
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
              <div className="space-y-2">
                <CardTitle>{selected.name}</CardTitle>
                <CardDescription className="break-all">
                  {selected.id} · {t("revision", { n: selected.revision })}
                </CardDescription>
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!!busy}
                  onClick={() => void action("get", async () => adopt(await rangeLoopApi.get(selected.id)))}
                >
                  <RefreshCwIcon />
                  {t("refresh")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!!busy}
                  onClick={() =>
                    void action("export", async () =>
                      downloadSecurityJSON(
                        await rangeLoopApi.export(selected.id),
                        `aegisloop-windows-${selected.id}.json`,
                      ),
                    )
                  }
                >
                  <DownloadIcon />
                  {t("export")}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {chain ? <ChainWorkflow cycle={selected} dirty={candidateDirty} /> : null}
              <Badge variant={active ? "default" : "secondary"}>
                {active ? <Spinner /> : null}
                {label(selected.status, Boolean(selected.current))}
              </Badge>
              {selected.error ? (
                <Alert variant="destructive">
                  <AlertDescription>{selected.error}</AlertDescription>
                </Alert>
              ) : null}
              <div className="grid gap-4 lg:grid-cols-2">
                <RangeRunView run={selected.baseline} phase="baseline" />
                {selected.current ? (
                  <RangeRunView run={selected.current} phase="rerun" />
                ) : (
                  <div className="flex items-center justify-center rounded-lg border border-dashed p-6 text-muted-foreground text-sm">
                    {t("rerunPending")}
                  </div>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  variant="outline"
                  disabled={
                    !!busy ||
                    active ||
                    !ready ||
                    !currentRun?.finished_at ||
                    ["failed", "interrupted"].includes(currentRun.status)
                  }
                  onClick={() =>
                    void action("collect", async () => {
                      adopt(await rangeLoopApi.collect(selected.id));
                      setNotice(t("collectionStarted"));
                    })
                  }
                >
                  {busy === "collect" ? <Spinner /> : <SearchIcon />}
                  {t("collect")}
                </Button>
                <p className="max-w-3xl text-muted-foreground text-xs leading-relaxed">{t("collectionHelp")}</p>
              </div>
              {active ? <p className="text-muted-foreground text-xs">{t("pollHelp")}</p> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{t("candidateTitle")}</CardTitle>
              <CardDescription>{t(chain ? "chain.candidateHelp" : "candidateHelp")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert>
                <AlertDescription>{t("managedDeployment")}</AlertDescription>
              </Alert>
              <Button
                variant="outline"
                disabled={!!busy || active || !ready || pairLocked || !baselineReady}
                onClick={() =>
                  void action("suggest", async () => {
                    const suggestion = await rangeLoopApi.suggest(selected.id);
                    setCandidateText(json(suggestion.candidate_rule));
                    setWarnings(suggestion.warnings ?? []);
                    setSuggestionExplanation(suggestion.explanation ?? null);
                    if (chain)
                      setCandidateNote((value) => value || suggestion.explanation?.summary || t("chain.defaultNote"));
                    setCandidateDirty(true);
                  })
                }
              >
                {busy === "suggest" ? <Spinner /> : <WandSparklesIcon />}
                {t("suggest")}
              </Button>
              <div className="grid gap-4 xl:grid-cols-2">
                <div className="space-y-2">
                  <h3 className="font-medium text-sm">{t("baselineRule")}</h3>
                  {isChainRule(selected.baseline_rule) ? (
                    <ChainProfile rule={selected.baseline_rule} />
                  ) : (
                    <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/20 p-3 text-xs">
                      {json(selected.baseline_rule)}
                    </pre>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor={chain ? undefined : "range-candidate"}>
                    {t(chain ? "chain.candidateRule" : "candidateRule")}
                  </Label>
                  {chain ? (
                    <div className="space-y-3">
                      {(["task_behavior"] as const).map((profile) => (
                        <button
                          key={profile}
                          type="button"
                          disabled={!!busy || active || pairLocked || !baselineReady}
                          aria-pressed={chainDraft?.profile === profile}
                          className={`w-full space-y-2 rounded-md border p-3 text-left text-sm transition-colors hover:bg-muted/50 disabled:opacity-50 ${chainDraft?.profile === profile ? "border-sky-500/60 bg-sky-500/5" : ""}`}
                          onClick={() => {
                            setCandidateText(
                              json({
                                kind: "scheduled_task_chain",
                                name: t(`chain.profiles.${profile}.title`),
                                profile,
                              }),
                            );
                            setCandidateDirty(true);
                          }}
                        >
                          <span className="flex items-center gap-2 font-medium">
                            {chainDraft?.profile === profile ? (
                              <CheckCircle2Icon className="size-4 text-sky-600" />
                            ) : null}
                            {t(`chain.profiles.${profile}.title`)}
                          </span>
                          <span className="block text-muted-foreground text-xs leading-relaxed">
                            {t(`chain.profiles.${profile}.description`)}
                          </span>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <Textarea
                      id="range-candidate"
                      className="font-mono text-xs"
                      rows={10}
                      value={candidateText}
                      disabled={!!busy || active || pairLocked}
                      onChange={(event) => {
                        setCandidateText(event.target.value);
                        setCandidateDirty(true);
                      }}
                    />
                  )}
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="range-note">{t("candidateNote")}</Label>
                <Textarea
                  id="range-note"
                  rows={2}
                  maxLength={2000}
                  value={candidateNote}
                  disabled={!!busy || active || pairLocked}
                  onChange={(event) => {
                    setCandidateNote(event.target.value);
                    setCandidateDirty(true);
                  }}
                />
              </div>
              {warnings.length ? (
                <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-sm">
                  {warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              ) : null}
              {chain && suggestionExplanation ? (
                <div className="space-y-3 rounded-lg border bg-muted/20 p-4 text-sm">
                  <p className="font-medium">{suggestionExplanation.summary}</p>
                  {(["causes", "evidence", "improvements", "limitations"] as const).map((key) =>
                    suggestionExplanation[key]?.length ? (
                      <div key={key} className="space-y-1">
                        <h4 className="font-medium text-xs">{t(`chain.explanation.${key}`)}</h4>
                        <ul className="list-disc space-y-1 pl-4 text-muted-foreground text-xs">
                          {suggestionExplanation[key].map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null,
                  )}
                </div>
              ) : null}
              <div className="flex flex-wrap gap-3">
                <Button
                  disabled={
                    !!busy ||
                    active ||
                    !ready ||
                    pairLocked ||
                    !baselineReady ||
                    !candidateText.trim() ||
                    !candidateNote.trim() ||
                    !candidateDirty
                  }
                  onClick={() =>
                    void action("candidate", async () => {
                      const rule = parseRule();
                      adopt(
                        await rangeLoopApi.candidate(selected.id, {
                          expected_revision: selected.revision,
                          rule,
                          note: candidateNote.trim(),
                        }),
                        true,
                      );
                      setNotice(t("deploymentStarted"));
                    })
                  }
                >
                  {busy === "candidate" ? <Spinner /> : <SaveIcon />}
                  {t("applyCandidate")}
                </Button>
                <Button
                  variant="outline"
                  disabled={
                    !!busy ||
                    active ||
                    !ready ||
                    pairLocked ||
                    !selected.candidate_rule ||
                    candidateDirty ||
                    selected.status !== "candidate_ready"
                  }
                  onClick={() =>
                    void action("rerun", async () => {
                      adopt(await rangeLoopApi.rerun(selected.id, selected.revision));
                      setNotice(t("rerunStarted"));
                    })
                  }
                >
                  {busy === "rerun" ? <Spinner /> : <Repeat2Icon />}
                  {t("rerun")}
                </Button>
              </div>
              {candidateDirty ? <p className="text-amber-700 text-sm dark:text-amber-300">{t("dirty")}</p> : null}
              {chain && selected.baseline.evidence && !baselineReady ? (
                <p className="text-amber-700 text-sm dark:text-amber-300">{t("chain.needComplete")}</p>
              ) : null}
              {pairLocked ? <p className="text-muted-foreground text-sm">{t("pairLocked")}</p> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{t("comparisonTitle")}</CardTitle>
              <CardDescription>{t("comparisonHelp")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {chain ? (
                <ChainComparison cycle={selected} />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("scenario")}</TableHead>
                      <TableHead>{t("baseline")}</TableHead>
                      <TableHead>{t("rerunPhase")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selected.scenario_ids.map((id) => (
                      <TableRow key={id}>
                        <TableCell>{scenarios.find((s) => s.id === id)?.name ?? id}</TableCell>
                        <TableCell>{evidenceVerdict(selected.baseline.evidence, id, t)}</TableCell>
                        <TableCell>{evidenceVerdict(selected.current?.evidence, id, t)}</TableCell>
                      </TableRow>
                    ))}
                    <TableRow>
                      <TableCell className="font-medium">{t("detectedCount")}</TableCell>
                      <TableCell>
                        {selected.baseline.evidence
                          ? `${selected.comparison.baseline_detected} / ${selected.comparison.total_scenarios}`
                          : t("notCollected")}
                      </TableCell>
                      <TableCell>
                        {selected.current?.evidence
                          ? `${selected.comparison.current_detected} / ${selected.comparison.total_scenarios}`
                          : t("notCollected")}
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              )}
              <Badge variant={selected.comparison.comparable ? "default" : "secondary"}>
                {t(selected.comparison.comparable ? "comparable" : "notComparable")}
              </Badge>
              {(selected.comparison.reasons ?? []).length ? (
                <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-sm">
                  {selected.comparison.reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : null}
              <p className="text-muted-foreground text-xs leading-relaxed">
                {t(chain ? "chain.metricBoundary" : "metricBoundary")}
              </p>
              {chain && selected.current?.evidence ? (
                <Button
                  variant="outline"
                  disabled={!!busy || active}
                  onClick={() => {
                    setScenarioIDs(["ps_task_chain"]);
                    setName(t("chain.nextName", { name: selected.name }).slice(0, 120));
                    selectedID.current = null;
                    setSelected(null);
                    const url = new URL(window.location.href);
                    url.searchParams.delete("cycle");
                    window.history.replaceState(null, "", url);
                    setNotice("");
                    setError("");
                    window.scrollTo({ top: 0, behavior: "smooth" });
                  }}
                >
                  <Repeat2Icon />
                  {t("chain.nextVerification")}
                </Button>
              ) : null}
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}

function evidenceVerdict(
  evidence: RangeEvidence | null | undefined,
  id: string,
  t: ReturnType<typeof useTranslations>,
) {
  if (!evidence) return t("notCollected");
  if (evidence.detected_scenarios?.includes(id)) return t("detected");
  if (evidence.missed_scenarios?.includes(id) && evidence.complete) return t("missed");
  return t("unknown");
}

function RangeRunView({ run, phase }: { run: RangeRun; phase: "baseline" | "rerun" }) {
  const t = useTranslations("RangeLoop");
  const statusLabel = (value: string) => (t.has(`status.${value}`) ? t(`status.${value}`) : value);
  return (
    <div className="space-y-3 rounded-lg border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-medium">{t(phase === "baseline" ? "baseline" : "rerunPhase")}</h3>
        <Badge variant="secondary">
          {run.status === "running" && phase === "rerun" ? t("status.rerunning") : statusLabel(run.status)}
        </Badge>
      </div>
      <p className="break-all font-mono text-xs">{run.id}</p>
      <p className="text-muted-foreground text-xs">
        {time(run.started_at)} → {time(run.finished_at)}
      </p>
      {(run.results ?? []).map((result) => (
        <div key={result.scenario_id} className="space-y-1 rounded-md bg-muted/30 p-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{result.name}</span>
            <Badge variant="outline">{statusLabel(result.status)}</Badge>
          </div>
          <p className="text-muted-foreground text-xs">
            {t("exitCode")}: {result.exit_code ?? "—"}
          </p>
          {result.summary ? (
            <p className="whitespace-pre-wrap break-words text-muted-foreground text-xs">{result.summary}</p>
          ) : null}
        </div>
      ))}
      {run.evidence ? (
        <div className="space-y-3 border-t pt-3">
          {run.evidence.cases ? <ChainEvidenceView evidence={run.evidence} /> : null}
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={run.evidence.complete ? "outline" : "secondary"}>
              {t(run.evidence.complete ? "complete" : "incomplete")}
            </Badge>
            <span className="text-muted-foreground text-xs">
              {t("eventCounts", { audits: run.evidence.audit_count, alerts: run.evidence.alert_count })}
            </span>
          </div>
          {(run.evidence.warnings ?? []).length ? (
            <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-xs">
              {run.evidence.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
          {run.evidence.events?.length ? (
            <details className="rounded-md border p-3">
              <summary className="cursor-pointer font-medium text-sm">{t("evidenceEvents")}</summary>
              <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-all text-xs">
                {json(run.evidence.events)}
              </pre>
            </details>
          ) : (
            <p className="text-muted-foreground text-xs">{t("rawInExport")}</p>
          )}
        </div>
      ) : (
        <p className="text-muted-foreground text-sm">{t("notCollected")}</p>
      )}
    </div>
  );
}

function ChainProfile({ rule }: { rule: ChainRule }) {
  const t = useTranslations("RangeLoop");
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-4">
      <Badge variant="outline">{t(`chain.profiles.${rule.profile}.title`)}</Badge>
      <p className="font-medium text-sm">{rule.name}</p>
      <p className="text-muted-foreground text-xs leading-relaxed">{t(`chain.profiles.${rule.profile}.description`)}</p>
      <details>
        <summary className="cursor-pointer text-muted-foreground text-xs">{t("chain.ruleDefinition")}</summary>
        <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">{json(rule)}</pre>
      </details>
    </div>
  );
}

function ChainWorkflow({ cycle, dirty }: { cycle: RangeCycle; dirty: boolean }) {
  const t = useTranslations("RangeLoop");
  const baselineReady = cycle.baseline.evidence?.complete && cycle.comparison.baseline_metrics?.unknown === 0;
  const currentReady =
    cycle.current?.evidence?.complete &&
    cycle.comparison.current_metrics?.unknown === 0 &&
    !cycle.current.evidence.metrics?.unknown;
  const step = ACTIVE.has(cycle.status)
    ? "inProgress"
    : !cycle.baseline.evidence
      ? "collect"
      : !baselineReady
        ? "evidenceGap"
        : !cycle.candidate_rule || dirty || (cycle.status !== "candidate_ready" && !cycle.current)
          ? "improve"
          : !cycle.current
            ? "rerun"
            : !cycle.current.evidence
              ? "collect"
              : !currentReady
                ? "evidenceGap"
                : "compare";
  return (
    <div className="space-y-3 rounded-lg border bg-sky-500/5 p-4">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <WorkflowIcon className="size-4 text-sky-600" />
        {(["baseline", "evidence", "improve", "rerun", "compare"] as const).map((name, index) => (
          <React.Fragment key={name}>
            {index ? <ChevronRightIcon className="size-3 text-muted-foreground" /> : null}
            <span>
              {index + 1}. {t(`chain.steps.${name}`)}
            </span>
          </React.Fragment>
        ))}
      </div>
      <p className="font-medium text-sm">{t(`chain.next.${step}`)}</p>
    </div>
  );
}

function ChainMetricsView({ metrics }: { metrics: RangeMetrics | null | undefined }) {
  const t = useTranslations("RangeLoop");
  if (!metrics) return <p className="text-muted-foreground text-sm">{t("notCollected")}</p>;
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <div className="space-y-1 rounded-md border bg-emerald-500/5 p-3">
        <p className="text-muted-foreground text-xs">{t("chain.attackDetection")}</p>
        <p className="font-semibold text-lg">
          {t("chain.tpCount", { tp: metrics.true_positives, total: metrics.attack_total })}
        </p>
        <p className="text-muted-foreground text-xs">{t("chain.fnCount", { n: metrics.false_negatives })}</p>
      </div>
      <div className="space-y-1 rounded-md border bg-amber-500/5 p-3">
        <p className="text-muted-foreground text-xs">{t("chain.benignFalsePositive")}</p>
        <p className="font-semibold text-lg">
          {t("chain.fpCount", { fp: metrics.false_positives, total: metrics.benign_total })}
        </p>
        <p className="text-muted-foreground text-xs">{t("chain.tnCount", { n: metrics.true_negatives })}</p>
      </div>
      {metrics.unknown ? (
        <p className="text-amber-700 text-xs sm:col-span-2 dark:text-amber-300">
          {t("chain.unknownCount", { n: metrics.unknown })}
        </p>
      ) : null}
    </div>
  );
}

function ChainComparison({ cycle }: { cycle: RangeCycle }) {
  const t = useTranslations("RangeLoop");
  const heldout = cycle.comparison.heldout_variant;
  const commonIDs = cycle.comparison.common_case_ids ?? ["chain_attack", "chain_benign"];
  return (
    <div className="space-y-4">
      <p className="text-muted-foreground text-sm">{t("chain.commonComparison")}</p>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-2">
          <h3 className="font-medium text-sm">{t("baseline")}</h3>
          <ChainMetricsView metrics={cycle.comparison.baseline_metrics} />
        </div>
        <div className="space-y-2">
          <h3 className="font-medium text-sm">{t("rerunPhase")}</h3>
          <ChainMetricsView metrics={cycle.comparison.current_metrics} />
        </div>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("chain.case")}</TableHead>
            <TableHead>{t("baseline")}</TableHead>
            <TableHead>{t("rerunPhase")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {commonIDs.map((id) => {
            const before = cycle.baseline.evidence?.cases?.find((item) => item.case_id === id);
            const after = cycle.current?.evidence?.cases?.find((item) => item.case_id === id);
            return (
              <TableRow key={id}>
                <TableCell>{before?.label ?? after?.label ?? t(`chain.caseNames.${id}`)}</TableCell>
                <TableCell>
                  <ChainVerdict caseRecord={before} />
                </TableCell>
                <TableCell>
                  <ChainVerdict caseRecord={after} />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <div className="space-y-2 rounded-lg border border-dashed p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline">{t("chain.heldout")}</Badge>
          <span className="font-medium text-sm">{heldout?.label ?? t("chain.caseNames.chain_variant")}</span>
          <ChainVerdict caseRecord={heldout} />
        </div>
        <p className="text-muted-foreground text-xs leading-relaxed">{t("chain.heldoutHelp")}</p>
        {heldout?.reason ? <p className="text-sm">{heldout.reason}</p> : null}
      </div>
    </div>
  );
}

function ChainVerdict({ caseRecord }: { caseRecord: RangeCase | null | undefined }) {
  const t = useTranslations("RangeLoop");
  if (!caseRecord) return <span className="text-muted-foreground text-xs">{t("notCollected")}</span>;
  return (
    <Badge
      variant={caseRecord.verdict === "detected" || caseRecord.verdict === "true_negative" ? "outline" : "secondary"}
    >
      {t(`chain.verdict.${caseRecord.verdict}`)}
    </Badge>
  );
}

function ChainEvidenceView({ evidence }: { evidence: RangeEvidence }) {
  const t = useTranslations("RangeLoop");
  return (
    <div className="space-y-4">
      <ChainMetricsView metrics={evidence.metrics} />
      {evidence.analysis ? (
        <div className="space-y-3 rounded-md bg-muted/30 p-3 text-sm">
          <p className="font-medium">{evidence.analysis.summary}</p>
          {(["gaps", "recommendations"] as const).map((key) =>
            evidence.analysis?.[key]?.length ? (
              <div key={key} className="space-y-1">
                <h4 className="font-medium text-xs">{t(`chain.analysis.${key}`)}</h4>
                <ul className="list-disc space-y-1 pl-4 text-muted-foreground text-xs">
                  {evidence.analysis[key].map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null,
          )}
        </div>
      ) : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("chain.case")}</TableHead>
            <TableHead>{t("chain.verdictTitle")}</TableHead>
            <TableHead>{t("chain.alertCount")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(evidence.cases ?? []).map((item) => (
            <TableRow key={item.case_id}>
              <TableCell>
                <p className="font-medium text-xs">{item.label}</p>
                <p className="text-muted-foreground text-xs">
                  {t(`chain.expected.${item.expected}`)} ·{" "}
                  {t(item.execution_verified ? "chain.executionVerified" : "chain.executionUnknown")}
                </p>
              </TableCell>
              <TableCell>
                <ChainVerdict caseRecord={item} />
              </TableCell>
              <TableCell>{item.alert_count}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {(evidence.cases ?? []).map((item) => (
        <details key={item.case_id} className="rounded-md border p-3">
          <summary className="cursor-pointer font-medium text-sm">
            {item.label} · {t("chain.stageEvidence")}
          </summary>
          <div className="mt-3 space-y-3">
            <p className="text-muted-foreground text-xs leading-relaxed">{item.reason}</p>
            {item.latency_seconds !== null ? (
              <p className="text-muted-foreground text-xs">{t("chain.caseLatency", { n: item.latency_seconds })}</p>
            ) : null}
            {(item.stages ?? []).map((stage, index) => (
              <div key={`${stage.name}-${index}`} className="relative space-y-1 border-sky-500/30 border-l-2 pl-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-xs">{stage.name}</span>
                  <Badge variant="outline">{t(`chain.stageStatus.${stage.status}`)}</Badge>
                </div>
                <p className="text-muted-foreground text-xs">{time(stage.time)}</p>
                <p className="break-words text-xs leading-relaxed">{stage.evidence}</p>
              </div>
            ))}
          </div>
        </details>
      ))}
      {evidence.timeline?.length ? (
        <details className="rounded-md border p-3">
          <summary className="cursor-pointer font-medium text-sm">
            {t("chain.timeline", { n: evidence.timeline.length })}
          </summary>
          <div className="mt-3 max-h-96 space-y-3 overflow-auto">
            {evidence.timeline.map((event, index) => (
              <div key={`${event.case_id}-${event.time}-${index}`} className="space-y-1 border-l-2 pl-3 text-xs">
                <p className="text-muted-foreground">
                  {time(event.time)} · {event.source} · {event.event_code}
                </p>
                <Badge variant="outline">
                  {evidence.cases?.find((item) => item.case_id === event.case_id)?.label ?? event.case_id}
                </Badge>
                <p className="font-medium">
                  {event.action}
                  {event.process_image ? ` · ${event.process_image}` : ""}
                </p>
                <p className="break-words leading-relaxed">{event.summary}</p>
              </div>
            ))}
          </div>
        </details>
      ) : null}
      <p className="text-muted-foreground text-xs">{t("chain.sourceBoundary")}</p>
    </div>
  );
}

"use client";

import * as React from "react";

import Link from "next/link";

import {
  ArrowRightIcon,
  ArrowUpRightIcon,
  FileSearchIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  TargetIcon,
  WorkflowIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { type AegisOverview, aegisApi, type DefensiveCaseSummary, defensiveApi } from "@/lib/defensive-api";

export default function DashboardPage() {
  const t = useTranslations("Aegis");
  const [data, setData] = React.useState<AegisOverview | null>(null);
  const [cases, setCases] = React.useState<DefensiveCaseSummary[]>([]);
  const [error, setError] = React.useState("");
  const [caseError, setCaseError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const refresh = React.useCallback(async () => {
    setLoading(true);
    const results = await Promise.allSettled([aegisApi.overview(), defensiveApi.list()]);
    if (results[0].status === "fulfilled") {
      setData(results[0].value);
      setError("");
    } else setError((results[0].reason as Error).message);
    if (results[1].status === "fulfilled") {
      setCases(results[1].value.cases ?? []);
      setCaseError("");
    } else setCaseError((results[1].reason as Error).message);
    setLoading(false);
  }, []);
  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const areas = [
    {
      id: "offensive",
      href: "/offensive/",
      icon: TargetIcon,
      color: "text-orange-600 dark:text-orange-400",
      count: data?.offensive.tasks,
      metric: "tasks",
      secondary: data
        ? t("overview.offensiveCounts", {
            active: data.offensive.active_tasks,
            findings: data.offensive.findings,
            assets: data.offensive.assets,
          })
        : "",
    },
    {
      id: "defensive",
      href: "/defensive/",
      icon: ShieldCheckIcon,
      color: "text-sky-600 dark:text-sky-400",
      count: data?.defensive.cases,
      metric: "cases",
      secondary: data
        ? t("overview.defensiveCounts", { active: data.defensive.active_runs, sources: data.defensive.sources })
        : "",
    },
    {
      id: "closedLoop",
      href: "/closed-loop/",
      icon: WorkflowIcon,
      color: "text-violet-600 dark:text-violet-400",
      count: data?.closed_loop.cycles,
      metric: "cycles",
      secondary: t("overview.loopCounts"),
    },
  ];
  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-2">
          <Badge variant="outline">AegisLoop</Badge>
          <h1 className="text-2xl font-semibold tracking-tight">{t("overview.title")}</h1>
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{t("overview.description")}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void refresh()} disabled={loading}>
          <RefreshCwIcon className={loading ? "animate-spin" : ""} />
          {t("refresh")}
        </Button>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-3">
        {areas.map((area) => (
          <Card key={area.id} className="relative overflow-hidden">
            <CardHeader>
              <div className="flex items-center justify-between">
                <area.icon className={`size-6 ${area.color}`} />
                <Badge variant="secondary">{t(`overview.area.${area.id}`)}</Badge>
              </div>
              <CardTitle className="pt-2">{t(`overview.area.${area.id}`)}</CardTitle>
              <CardDescription className="min-h-10 leading-relaxed">{t(`overview.help.${area.id}`)}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-baseline gap-2">
                {loading && !data ? (
                  <Skeleton className="h-9 w-12" />
                ) : (
                  <span className="text-3xl font-semibold tabular-nums">{area.count ?? "—"}</span>
                )}
                <span className="text-sm text-muted-foreground">{t(`overview.metric.${area.metric}`)}</span>
              </div>
              <p className="min-h-8 text-xs leading-relaxed text-muted-foreground">{area.secondary}</p>
              <Button asChild className="w-full" variant="outline">
                <Link href={area.href}>
                  {t("open")}
                  <ArrowUpRightIcon />
                </Link>
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
      <Card className="border-violet-500/20 bg-gradient-to-r from-violet-500/5 via-background to-sky-500/5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <WorkflowIcon className="size-5 text-violet-500" />
            {t("overview.flowTitle")}
          </CardTitle>
          <CardDescription>{t("overview.flowHelp")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid items-center gap-3 md:grid-cols-[1fr_auto_1fr_auto_1fr]">
            {["attack", "defend", "improve"].map((step, i) => (
              <React.Fragment key={step}>
                {i ? <ArrowRightIcon className="hidden size-4 text-muted-foreground md:block" /> : null}
                <div className="rounded-lg border bg-background/80 p-4">
                  <span className="text-xs font-medium text-muted-foreground">0{i + 1}</span>
                  <p className="mt-1 font-medium text-sm">{t(`overview.flow.${step}`)}</p>
                </div>
              </React.Fragment>
            ))}
          </div>
          <p className="mt-4 text-xs leading-relaxed text-muted-foreground">{t("overview.metricsBoundary")}</p>
        </CardContent>
      </Card>
      <div className="grid gap-4 lg:grid-cols-[1.5fr_1fr]">
        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-3">
            <div className="space-y-1.5">
              <CardTitle className="text-base">{t("overview.recentCases")}</CardTitle>
              <CardDescription>{t("overview.recentHelp")}</CardDescription>
            </div>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/defensive/">
                {t("all")}
                <ArrowRightIcon />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {caseError ? (
              <Alert variant="destructive">
                <AlertDescription>{caseError}</AlertDescription>
              </Alert>
            ) : null}
            {!cases.length && !caseError ? (
              <div className="rounded-lg border border-dashed p-6 text-center">
                <FileSearchIcon className="mx-auto mb-3 size-6 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">{loading ? t("loading") : t("overview.emptyCases")}</p>
                <Button className="mt-4" size="sm" asChild>
                  <Link href="/defensive/?new=1">{t("defensive.newCase")}</Link>
                </Button>
              </div>
            ) : (
              cases.slice(0, 4).map((item) => (
                <Link
                  key={item.id}
                  href={`/defensive/?case=${encodeURIComponent(item.id)}`}
                  className="block space-y-2 rounded-lg border p-4 transition-colors hover:bg-muted/50"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-sm">{item.title}</span>
                    <Badge variant="outline">{item.source_kind === "splunk" ? "Splunk" : t("defensive.file")}</Badge>
                    <span className="ml-auto text-xs text-muted-foreground">
                      {new Date(item.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="line-clamp-2 text-sm text-muted-foreground">{item.summary}</p>
                </Link>
              ))
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("overview.startTitle")}</CardTitle>
            <CardDescription>{t("overview.startHelp")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { href: "/function/tasks/", icon: TargetIcon, key: "attack" },
              { href: "/defensive/?new=1", icon: FileSearchIcon, key: "defend" },
              { href: "/closed-loop/", icon: WorkflowIcon, key: "improve" },
            ].map((item) => (
              <Link
                key={item.key}
                href={item.href}
                className="flex items-center gap-3 rounded-lg border p-4 transition-colors hover:bg-muted/50"
              >
                <item.icon className="size-5 shrink-0 text-muted-foreground" />
                <div>
                  <p className="font-medium text-sm">{t(`overview.start.${item.key}`)}</p>
                  <p className="mt-1 text-xs text-muted-foreground">{t(`overview.startHint.${item.key}`)}</p>
                </div>
                <ArrowRightIcon className="ml-auto size-4 shrink-0" />
              </Link>
            ))}
          </CardContent>
        </Card>
      </div>
      {data ? (
        <p className="text-right text-xs text-muted-foreground">
          {t("overview.generated", { at: new Date(data.generated_at).toLocaleString() })}
        </p>
      ) : null}
    </div>
  );
}

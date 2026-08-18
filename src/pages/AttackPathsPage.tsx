import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Network,
  Loader2,
  AlertCircle,
  GitBranch,
  ArrowRight,
  ShieldCheck,
  Target,
  RefreshCw,
  Crosshair,
} from "lucide-react";
import { supabase } from "@/lib/db";
import { ai, MAX_ATTACK_PATH_FINDINGS } from "@/lib/ai";
import type { Finding, AIAttackPathsResult, AttackPath, AttackPathStep } from "@/lib/types";
import { Panel, PageHeader, Button, EmptyState, SeverityBadge } from "@/components/ui-kit";
import { classNames } from "@/lib/utils";
import type { PageId } from "@/components/AppShell";

/**
 * AI responses are only shape-validated, so any leaf can still arrive as an
 * object or array. Everything rendered goes through this to avoid the React
 * "[object Object]" failure mode.
 */
function toText(value: unknown, depth = 0): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    return value
      .map((item) => toText(item, depth + 1))
      .filter(Boolean)
      .join(depth === 0 ? " → " : ", ");
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    for (const key of ["text", "detail", "description", "action", "value", "name", "label", "node"]) {
      const candidate = record[key];
      if (typeof candidate === "string" && candidate.trim()) return candidate;
    }
    if (depth > 2) return "";
    return Object.entries(record)
      .map(([key, val]) => {
        const rendered = toText(val, depth + 1);
        return rendered ? `${key.replace(/_/g, " ")}: ${rendered}` : "";
      })
      .filter(Boolean)
      .join(" · ");
  }
  return "";
}

type EvidenceKind = "detected" | "inferred" | "validated" | "unknown";

function evidenceKind(raw: unknown): EvidenceKind {
  const value = toText(raw).toLowerCase();
  if (/valid|verified|confirmed/.test(value)) return "validated";
  if (/infer|correlat|predict|assum/.test(value)) return "inferred";
  if (/detect|observ|found|scanned/.test(value)) return "detected";
  return "unknown";
}

const EVIDENCE_STYLE: Record<EvidenceKind, string> = {
  detected: "text-cyber-300 bg-cyber-500/10 border-cyber-500/25",
  validated: "text-volt-300 bg-volt-500/10 border-volt-500/25",
  inferred: "text-warning bg-warning/10 border-warning/25",
  unknown: "text-ink-400 bg-ink-700/40 border-ink-600/40",
};

const EVIDENCE_LABEL: Record<EvidenceKind, string> = {
  detected: "Detected",
  validated: "Validated",
  inferred: "Inferred (AI)",
  unknown: "Unclassified",
};

function EvidenceTag({ value, className }: { value: unknown; className?: string }) {
  const kind = evidenceKind(value);
  return (
    <span className={classNames("chip border text-[10px]", EVIDENCE_STYLE[kind], className)}>
      {EVIDENCE_LABEL[kind]}
    </span>
  );
}

function riskTone(score: number): string {
  if (score >= 80) return "text-danger bg-danger/15 border-danger/30";
  if (score >= 60) return "text-orange-400 bg-orange-500/15 border-orange-500/30";
  if (score >= 35) return "text-warning bg-warning/15 border-warning/30";
  return "text-ink-300 bg-ink-700/40 border-ink-600/40";
}

export function AttackPathsPage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [mode, setMode] = useState<"all" | "selected" | null>(null);
  const [result, setResult] = useState<AIAttackPathsResult | null>(null);
  const [analyzedIds, setAnalyzedIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [appContext, setAppContext] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [retestedAt, setRetestedAt] = useState<string | null>(null);
  const inFlight = useRef(false);

  useEffect(() => {
    let active = true;
    (async () => {
      const { data } = await supabase
        .from("findings")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);
      if (!active) return;
      setFindings((data as Finding[]) ?? []);
      setLoading(false);
    })();
    return () => {
      active = false;
    };
  }, []);

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  /** Both entry points share the exact same engine call — only the scope differs. */
  const runEngine = useCallback(
    async (scope: "all" | "selected", isRetest = false) => {
      if (inFlight.current) return;
      const subset =
        scope === "selected" ? findings.filter((f) => selected.has(f.id)) : findings;
      if (subset.length === 0) {
        setError("Select at least one finding to analyze.");
        return;
      }
      inFlight.current = true;
      setAnalyzing(true);
      setMode(scope);
      setError(null);
      if (!isRetest) setResult(null);
      setRetestedAt(null);
      try {
      const res = await ai.generateAttackPaths(
  subset as unknown as Record<string, unknown>[],
  appContext || "No additional context. Reconstruct attack paths from the findings.",
        );
        setResult(res);
        setAnalyzedIds(subset.slice(0, MAX_ATTACK_PATH_FINDINGS).map((f) => f.id));
        if (isRetest) setRetestedAt(new Date().toLocaleString());
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        inFlight.current = false;
        setAnalyzing(false);
      }
    },
    [findings, selected, appContext],
  );

  const retest = useCallback(async () => {
    if (inFlight.current) return;
    const { data } = await supabase
      .from("findings")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(100);
    const fresh = (data as Finding[]) ?? [];
    setFindings(fresh);
    const scopeIds = new Set(analyzedIds);
    const stillOpen = fresh.filter(
      (f) => scopeIds.has(f.id) && f.status !== "remediated" && f.status !== "verified",
    );
    if (stillOpen.length === 0) {
      setResult((prev) => (prev ? { ...prev, paths: [] } : prev));
      setRetestedAt(new Date().toLocaleString());
      return;
    }
    setSelected(new Set(stillOpen.map((f) => f.id)));
    await runEngine("selected", true);
  }, [analyzedIds, runEngine]);

  const paths = useMemo(() => (result?.paths ?? []) as AttackPath[], [result]);
  const topPath = paths[0];

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-cyber-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Attack-Path Engine"
        subtitle="Reconstruct entry point → vulnerability → attack step → impact chains, ranked by realistic risk."
        icon={<Network className="h-6 w-6" />}
        actions={
          <Button size="sm" variant="ghost" onClick={() => onNavigate("analyze")}>
            New Analysis
          </Button>
        }
      />

      {findings.length === 0 ? (
        <Panel className="p-8">
          <EmptyState
            icon={<Network className="h-12 w-12" />}
            title="No findings to analyze"
            description="Run a code analysis first. The attack-path engine uses your findings to reconstruct attack paths."
            action={<Button onClick={() => onNavigate("analyze")}>Go to Analyze</Button>}
          />
        </Panel>
      ) : (
        <>
          <Panel className="p-4">
            <label className="label">Application Context (optional)</label>
            <textarea
              value={appContext}
              onChange={(e) => setAppContext(e.target.value)}
              placeholder="Describe your application architecture, entry points, trust boundaries..."
              rows={3}
              className="textarea"
            />
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button onClick={() => runEngine("selected")} disabled={analyzing || selected.size === 0}>
                {analyzing && mode === "selected" ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Crosshair className="h-4 w-4" />
                )}
                Analyze Selected ({selected.size})
              </Button>
              <Button variant="ghost" onClick={() => runEngine("all")} disabled={analyzing}>
                {analyzing && mode === "all" ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Network className="h-4 w-4" />
                )}
                Analyze All ({findings.length})
              </Button>
              {result && (
                <Button variant="ghost" onClick={retest} disabled={analyzing}>
                  <RefreshCw className="h-4 w-4" />
                  Re-test after remediation
                </Button>
              )}
            </div>
            <p className="mt-2 text-xs text-ink-500">
              Up to {MAX_ATTACK_PATH_FINDINGS} findings are analyzed per run to keep results fast and precise.
            </p>
          </Panel>

          <Panel className="p-4">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-ink-100">Findings</h3>
              <div className="flex gap-2">
                <button
                  className="text-xs text-cyber-300 hover:underline"
                  onClick={() => setSelected(new Set(findings.slice(0, MAX_ATTACK_PATH_FINDINGS).map((f) => f.id)))}
                >
                  Select top {Math.min(findings.length, MAX_ATTACK_PATH_FINDINGS)}
                </button>
                <button className="text-xs text-ink-400 hover:underline" onClick={() => setSelected(new Set())}>
                  Clear
                </button>
              </div>
            </div>
            <div className="max-h-64 space-y-1 overflow-y-auto pr-1">
              {findings.map((f) => (
                <label
                  key={f.id}
                  className="flex cursor-pointer items-center gap-3 rounded-lg border border-ink-800/60 bg-ink-900/30 px-3 py-2 text-sm hover:border-cyber-500/30"
                >
                  <input
                    type="checkbox"
                    checked={selected.has(f.id)}
                    onChange={() => toggle(f.id)}
                    className="h-3.5 w-3.5 accent-current text-cyber-400"
                  />
                  <SeverityBadge severity={f.severity} />
                  <span className="flex-1 truncate text-ink-200">{toText(f.title)}</span>
                  <span className="truncate font-mono text-[10px] text-ink-500">{toText(f.file_path)}</span>
                </label>
              ))}
            </div>
          </Panel>

          {analyzing && (
            <Panel className="p-8 scanline">
              <div className="flex flex-col items-center text-center">
                <Loader2 className="h-8 w-8 animate-spin text-cyber-400" />
                <p className="mt-3 text-sm text-ink-300">Reconstructing attack paths...</p>
                <p className="mt-1 text-xs text-ink-500">
                  Correlating entry points, exploit steps, evidence and impact
                </p>
              </div>
            </Panel>
          )}

          {error && (
            <Panel className="p-4">
              <div className="flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{toText(error)}</span>
              </div>
            </Panel>
          )}

          {result && !analyzing && (
            <div className="space-y-4 animate-fade-in">
              {retestedAt && (
                <Panel className="p-3">
                  <p className="flex items-center gap-2 text-xs text-ink-300">
                    <ShieldCheck className="h-4 w-4 text-volt-300" />
                    Re-tested {retestedAt} —{" "}
                    {paths.length === 0
                      ? "no active attack paths remain; previous chains are broken."
                      : `${paths.length} attack path(s) still active.`}
                  </p>
                </Panel>
              )}

              {paths.length === 0 && !retestedAt && (
                <Panel className="p-6">
                  <EmptyState
                    icon={<ShieldCheck className="h-10 w-10" />}
                    title="No viable attack paths reconstructed"
                    description="The supplied evidence does not chain into a realistic attack path."
                  />
                </Panel>
              )}

              {topPath && (
                <Panel className="border-danger/30 p-4">
                  <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-danger">
                    <Target className="h-4 w-4" />
                    Highest-priority attack path
                  </div>
                  <p className="mt-1 text-sm font-semibold text-ink-100">{toText(topPath.name)}</p>
                  {topPath.why_this_path && (
                    <p className="mt-1 text-xs text-ink-400">{toText(topPath.why_this_path)}</p>
                  )}
                </Panel>
              )}

              {paths.map((path, i) => {
                const steps = (Array.isArray(path.steps) ? path.steps : []) as AttackPathStep[];
                const risk = typeof path.risk_score === "number" ? path.risk_score : 0;
                return (
                  <Panel key={path.id || i} className="p-4">
                    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyber-500/15 font-mono text-xs text-cyber-300">
                          {i + 1}
                        </span>
                        <span className="text-sm font-semibold text-ink-100">{toText(path.name)}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={classNames("chip border text-[10px]", riskTone(risk))}>
                          Risk {risk}
                        </span>
                        <EvidenceTag value={path.classification ?? path.status} />
                        <span
                          className={classNames(
                            "chip border text-[10px]",
                            path.status === "validated"
                              ? "text-danger bg-danger/15 border-danger/30"
                              : path.status === "reachable"
                                ? "text-orange-400 bg-orange-500/15 border-orange-500/30"
                                : "text-warning bg-warning/15 border-warning/30",
                          )}
                        >
                          {toText(path.status)}
                        </span>
                        <span className="font-mono text-xs text-ink-500">{path.confidence}% conf.</span>
                      </div>
                    </div>

                    {path.entry_point && (
                      <p className="mb-2 text-xs text-ink-400">
                        <span className="text-ink-500">Entry point:</span> {toText(path.entry_point)}
                      </p>
                    )}

                    {path.why_this_path && (
                      <div className="mb-3 rounded-lg border border-ink-700/60 bg-ink-900/40 p-2.5">
                        <p className="text-[10px] uppercase tracking-wider text-ink-500">Why this path?</p>
                        <p className="mt-1 text-xs text-ink-300">{toText(path.why_this_path)}</p>
                      </div>
                    )}

                    {steps.length > 0 && (
                      <div className="space-y-2">
                        {steps.map((step, j) => (
                          <div key={j} className="flex items-start gap-2 text-sm">
                            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-ink-800 font-mono text-[10px] text-ink-400">
                              {j + 1}
                            </span>
                            <div className="flex-1">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="text-ink-200">
                                  {toText(step.action) || toText(step.node)}
                                </span>
                                {step.classification && <EvidenceTag value={step.classification} />}
                                {step.mitre?.id && (
                                  <span className="chip border border-cyber-500/25 bg-cyber-500/10 text-[10px] text-cyber-300">
                                    {toText(step.mitre.id)}
                                    {step.mitre.name ? ` · ${toText(step.mitre.name)}` : ""}
                                  </span>
                                )}
                              </div>
                              {step.evidence && (
                                <p className="mt-0.5 text-xs text-ink-500">Evidence: {toText(step.evidence)}</p>
                              )}
                            </div>
                            {j < steps.length - 1 && <ArrowRight className="mt-1 h-3 w-3 text-ink-600" />}
                          </div>
                        ))}
                      </div>
                    )}

                    {path.impact && (
                      <div className="mt-3 rounded-lg border border-danger/20 bg-danger/5 p-2">
                        <p className="text-xs font-semibold text-danger">Impact: {toText(path.impact)}</p>
                      </div>
                    )}

                    {Array.isArray(path.evidence) && path.evidence.length > 0 && (
                      <div className="mt-3">
                        <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-500">Evidence</p>
                        <div className="space-y-1">
                          {path.evidence.map((ev, k) => (
                            <div key={k} className="flex items-start gap-2 text-xs text-ink-400">
                              <EvidenceTag value={ev?.classification} />
                              <span className="flex-1">
                                {toText(ev?.detail) || toText(ev)}
                                {ev?.source ? (
                                  <span className="ml-1 font-mono text-ink-600">({toText(ev.source)})</span>
                                ) : null}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {Array.isArray(path.remediation) && path.remediation.length > 0 && (
                      <div className="mt-3 rounded-lg border border-volt-500/20 bg-volt-500/5 p-2.5">
                        <p className="text-[10px] uppercase tracking-wider text-volt-300">Remediation</p>
                        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-ink-300">
                          {path.remediation.map((r, k) => (
                            <li key={k}>{toText(r)}</li>
                          ))}
                        </ul>
                        {path.break_condition && (
                          <p className="mt-1.5 text-[11px] text-ink-400">
                            Path is broken when: {toText(path.break_condition)}
                          </p>
                        )}
                      </div>
                    )}

                    {Array.isArray(path.prerequisites) && path.prerequisites.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {path.prerequisites.map((p, k) => (
                          <span
                            key={k}
                            className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400"
                          >
                            {toText(p)}
                          </span>
                        ))}
                      </div>
                    )}
                  </Panel>
                );
              })}

              {result.graph?.nodes?.length > 0 && (
                <Panel className="p-5">
                  <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
                    <GitBranch className="h-4 w-4 text-cyber-400" />
                    Security Graph
                  </h3>
                  <div className="overflow-x-auto">
                    <svg width="100%" height={Math.max(300, result.graph.nodes.length * 40)} className="min-w-[600px]">
                      {result.graph.edges.map((edge, i) => {
                        const nodes = result.graph.nodes;
                        const fromIdx = nodes.findIndex((n) => n.id === edge.from);
                        const toIdx = nodes.findIndex((n) => n.id === edge.to);
                        if (fromIdx < 0 || toIdx < 0) return null;
                        const cols = 4;
                        const fx = 80 + (fromIdx % cols) * 180 + 140;
                        const fy = 40 + Math.floor(fromIdx / cols) * 80 + 16;
                        const tx = 80 + (toIdx % cols) * 180;
                        const ty = 40 + Math.floor(toIdx / cols) * 80 + 16;
                        return (
                          <line
                            key={i}
                            x1={fx}
                            y1={fy}
                            x2={tx}
                            y2={ty}
                            stroke="#283449"
                            strokeWidth={1}
                            strokeDasharray="4 3"
                          />
                        );
                      })}
                      {result.graph.nodes.map((node, i) => {
                        const cols = 4;
                        const x = 80 + (i % cols) * 180;
                        const y = 40 + Math.floor(i / cols) * 80;
                        const typeColors: Record<string, string> = {
                          endpoint: "#ef4444",
                          function: "#f59e0b",
                          data_flow: "#0889b5",
                          cve: "#dc2626",
                          dependency: "#3366ff",
                          impact: "#ef4444",
                        };
                        const label = toText(node.label);
                        return (
                          <g key={node.id ?? i}>
                            <rect
                              x={x}
                              y={y}
                              width={140}
                              height={32}
                              rx={6}
                              fill="rgba(13,19,32,0.9)"
                              stroke={typeColors[node.type] ?? "#283449"}
                              strokeWidth={1.5}
                            />
                            <text x={x + 10} y={y + 20} fill="#b8c2d4" fontSize="11" fontFamily="monospace">
                              {label.length > 18 ? label.slice(0, 18) + "..." : label}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                </Panel>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

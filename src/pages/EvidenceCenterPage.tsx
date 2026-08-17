import { useState, useEffect, useMemo } from "react";
import {
  FolderSearch,
  Code2,
  GitCompareArrows,
  Activity,
  Brain,
  Loader2,
  ArrowRight,
} from "lucide-react";
import { supabase } from "@/lib/db";
import type { Finding, Classification } from "@/lib/types";
import type { PageId } from "@/components/AppShell";
import {
  Panel,
  PageHeader,
  Button,
  SeverityBadge,
  ExploitabilityBadge,
  ClassificationTag,
  EmptyState,
  StatCard,
  CodeBlock,
} from "@/components/ui-kit";
import { classNames } from "@/lib/utils";

type Lens = "code" | "data_flow" | "runtime" | "reasoning";

const LENSES: { id: Lens; label: string; icon: typeof Code2; hint: string }[] = [
  { id: "code", label: "Code evidence", icon: Code2, hint: "The exact snippets AegisCode observed" },
  { id: "data_flow", label: "Data flow", icon: GitCompareArrows, hint: "How untrusted input reaches the sink" },
  { id: "runtime", label: "Runtime evidence", icon: Activity, hint: "Behavioural and runtime observations" },
  { id: "reasoning", label: "Verdict reasoning", icon: Brain, hint: "Why AegisCode reached this verdict" },
];

export function EvidenceCenterPage({ onNavigate }: { onNavigate?: (page: PageId) => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [lens, setLens] = useState<Lens>("code");
  const [filter, setFilter] = useState<Classification | "all">("all");

  useEffect(() => {
    (async () => {
      const { data } = await supabase
        .from("findings")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);
      const rows = (data as Finding[]) ?? [];
      setFindings(rows);
      setSelectedId((prev) => prev ?? rows[0]?.id ?? null);
      setLoading(false);
    })();
  }, []);

  const selected = useMemo(
    () => findings.find((f) => f.id === selectedId) ?? null,
    [findings, selectedId],
  );

  const counts = useMemo(() => {
    let code = 0;
    let flow = 0;
    let runtime = 0;
    let verified = 0;
    for (const f of findings) {
      code += (f.evidence ?? []).filter((e) => e.type === "code" || e.type === "config").length;
      flow += (f.data_flow ?? []).length;
      runtime += (f.evidence ?? []).filter((e) => e.type === "behavior" || e.type === "runtime").length;
      verified += (f.evidence ?? []).filter((e) => e.classification === "verified").length;
    }
    return { code, flow, runtime, verified };
  }, [findings]);

  const evidenceForLens = (f: Finding) => {
    const items = f.evidence ?? [];
    if (lens === "code") return items.filter((e) => e.type === "code" || e.type === "config" || !e.type);
    if (lens === "runtime") return items.filter((e) => e.type === "behavior" || e.type === "runtime" || e.type === "response");
    return items;
  };

  const visible = (classification?: Classification) =>
    filter === "all" || classification === filter;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Evidence Center"
        subtitle="Code, data flow, runtime evidence and the exact reasoning behind every AegisCode verdict."
        icon={<FolderSearch className="h-6 w-6" />}
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Code evidence" value={counts.code} accent="cyber" />
        <StatCard label="Data-flow steps" value={counts.flow} accent="volt" />
        <StatCard label="Runtime evidence" value={counts.runtime} accent="warning" />
        <StatCard label="Verified items" value={counts.verified} accent="danger" />
      </div>

      {loading ? (
        <Panel className="flex items-center justify-center p-16">
          <Loader2 className="h-6 w-6 animate-spin text-cyber-400" />
        </Panel>
      ) : findings.length === 0 ? (
        <Panel className="p-10">
          <EmptyState
            icon={<FolderSearch className="h-8 w-8" />}
            title="No evidence yet"
            description="Run a code analysis first. Every finding carries its evidence chain, data flow and verdict reasoning here."
            action={onNavigate ? <Button onClick={() => onNavigate("analyze")}>Analyze code</Button> : undefined}
          />
        </Panel>
      ) : (
        <div className="grid gap-6 lg:grid-cols-5">
          <Panel className="p-4 lg:col-span-2">
            <p className="stat-label mb-3">Findings</p>
            <ul className="max-h-[36rem] space-y-2 overflow-y-auto pr-1">
              {findings.map((f) => (
                <li key={f.id}>
                  <button
                    onClick={() => setSelectedId(f.id)}
                    className={classNames(
                      "w-full rounded-lg skeu-screen p-3 text-left transition-colors",
                      selectedId === f.id && "ring-1 ring-cyber-500/40",
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="min-w-0 truncate text-xs font-semibold text-ink-100">{f.title}</span>
                    </div>
                    <p className="mt-1 flex items-center gap-2 text-[11px] text-ink-500">
                      <span className="truncate font-mono">{f.file_path || f.location || "unknown location"}</span>
                    </p>
                    <p className="mt-1 text-[11px] text-ink-500">
                      {(f.evidence ?? []).length} evidence · {(f.evidence_chain ?? []).length} chain ·{" "}
                      {(f.data_flow ?? []).length} flow
                    </p>
                  </button>
                </li>
              ))}
            </ul>
          </Panel>

          <div className="space-y-4 lg:col-span-3">
            {selected && (
              <>
                <Panel className="p-5">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={selected.severity} />
                    <h2 className="text-sm font-semibold text-ink-100">{selected.title}</h2>
                    <ExploitabilityBadge exploitability={selected.exploitability} />
                    <ClassificationTag classification={selected.reachability} />
                  </div>
                  {onNavigate && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="mt-3"
                      onClick={() => {
                        window.sessionStorage.setItem("aegis.finding", selected.id);
                        onNavigate("finding");
                      }}
                    >
                      <span className="flex items-center gap-1.5">
                        Open finding details <ArrowRight className="h-3 w-3" />
                      </span>
                    </Button>
                  )}

                  <div className="mt-4 flex flex-wrap gap-2">
                    {LENSES.map((l) => {
                      const Icon = l.icon;
                      return (
                        <button
                          key={l.id}
                          onClick={() => setLens(l.id)}
                          className={classNames(
                            "flex items-center gap-1.5 rounded-lg skeu-bezel px-3 py-1.5 text-xs transition-colors",
                            lens === l.id ? "text-cyber-200" : "text-ink-400 hover:text-ink-200",
                          )}
                        >
                          <Icon className="h-3.5 w-3.5" />
                          {l.label}
                        </button>
                      );
                    })}
                  </div>
                  <p className="mt-2 text-[11px] text-ink-500">
                    {LENSES.find((l) => l.id === lens)?.hint}
                  </p>

                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <span className="stat-label">Classification</span>
                    {(["all", "observed", "verified", "inferred", "unknown"] as const).map((c) => (
                      <button
                        key={c}
                        onClick={() => setFilter(c as Classification | "all")}
                        className={classNames(
                          "rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                          filter === c ? "bg-cyber-500/20 text-cyber-200" : "bg-ink-800 text-ink-400",
                        )}
                      >
                        {c}
                      </button>
                    ))}
                  </div>
                </Panel>

                {lens === "reasoning" ? (
                  <Panel className="p-5">
                    <p className="stat-label mb-2">Why AegisCode reached this verdict</p>
                    <div className="rounded-lg skeu-screen p-4 text-xs leading-relaxed text-ink-300">
                      {selected.verdict?.reasoning || "No verdict reasoning recorded for this finding."}
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-ink-400">
                      <span>
                        Exploitable in this app:{" "}
                        <span className="text-ink-200">
                          {selected.verdict?.exploitable_in_this_app === true
                            ? "yes"
                            : selected.verdict?.exploitable_in_this_app === false
                              ? "no"
                              : "undetermined"}
                        </span>
                      </span>
                      <span className="font-mono">
                        {Math.round((selected.verdict?.confidence ?? selected.exploit_confidence ?? 0) * 100)}%
                        confidence
                      </span>
                      {selected.verdict?.classification && (
                        <ClassificationTag classification={selected.verdict.classification} />
                      )}
                    </div>

                    {(selected.evidence_chain ?? []).length > 0 && (
                      <div className="mt-5">
                        <p className="stat-label mb-2">Evidence chain</p>
                        <ol className="space-y-2">
                          {(selected.evidence_chain ?? [])
                            .filter((n) => visible(n.classification))
                            .map((n, i) => (
                              <li key={i} className="rounded-lg skeu-screen p-3">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="font-mono text-[11px] text-ink-500">#{n.step ?? i + 1}</span>
                                  <span className="text-xs font-semibold text-ink-200">{n.node}</span>
                                  <span className="text-[10px] uppercase tracking-wider text-ink-500">
                                    {n.node_type}
                                  </span>
                                  {n.classification && <ClassificationTag classification={n.classification} />}
                                </div>
                                <p className="mt-1 text-xs text-ink-400">{n.detail}</p>
                              </li>
                            ))}
                        </ol>
                      </div>
                    )}
                  </Panel>
                ) : lens === "data_flow" ? (
                  <Panel className="p-5">
                    <p className="stat-label mb-3">Data flow: source → sink</p>
                    {(selected.data_flow ?? []).length === 0 ? (
                      <p className="text-xs text-ink-500">No data-flow trace recorded for this finding.</p>
                    ) : (
                      <ol className="space-y-2">
                        {(selected.data_flow ?? []).map((n, i) => (
                          <li key={i} className="flex items-start gap-3 rounded-lg skeu-screen p-3">
                            <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full skeu-bezel font-mono text-[11px] text-cyber-300">
                              {n.step ?? i + 1}
                            </span>
                            <div className="min-w-0">
                              <p className="font-mono text-xs text-ink-200">{n.point}</p>
                              <p className="mt-1 text-xs text-ink-400">{n.detail}</p>
                            </div>
                          </li>
                        ))}
                      </ol>
                    )}
                  </Panel>
                ) : (
                  <Panel className="p-5">
                    <p className="stat-label mb-3">
                      {lens === "code" ? "Code & configuration evidence" : "Runtime & behavioural evidence"}
                    </p>
                    {evidenceForLens(selected).filter((e) => visible(e.classification)).length === 0 ? (
                      <p className="text-xs text-ink-500">No evidence of this kind for this finding.</p>
                    ) : (
                      <div className="space-y-3">
                        {evidenceForLens(selected)
                          .filter((e) => visible(e.classification))
                          .map((e, i) => (
                            <div key={i} className="rounded-lg border border-ink-800 p-3">
                              <div className="mb-2 flex flex-wrap items-center gap-2">
                                <span className="text-[10px] uppercase tracking-wider text-ink-500">
                                  {e.type || "evidence"}
                                </span>
                                {e.classification && <ClassificationTag classification={e.classification} />}
                              </div>
                              {e.snippet && <CodeBlock code={e.snippet} />}
                              {e.explanation && <p className="mt-2 text-xs text-ink-400">{e.explanation}</p>}
                            </div>
                          ))}
                      </div>
                    )}
                  </Panel>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

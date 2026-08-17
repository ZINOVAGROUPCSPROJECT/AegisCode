import { useEffect, useState } from "react";
import { Network, Loader2, AlertCircle, GitBranch, ArrowRight } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { Finding, AIAttackPathsResult } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  EmptyState,
  ClassificationTag,
} from "@/components/ui-kit";
import { classNames } from "@/lib/utils";
import type { PageId } from "@/components/AppShell";

export function AttackPathsPage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AIAttackPathsResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [appContext, setAppContext] = useState("");

  useEffect(() => {
    (async () => {
      const { data } = await supabase
        .from("findings")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);
      setFindings((data as Finding[]) ?? []);
      setLoading(false);
    })();
  }, []);

  const runEngine = async () => {
    setAnalyzing(true);
    setError(null);
    setResult(null);
    try {
      const res = await ai.generateAttackPaths(
        findings as unknown as Record<string, unknown>[],
        appContext || "No additional context. Reconstruct attack paths from the findings."
      );
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setAnalyzing(false);
    }
  };

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
        subtitle="Reconstruct and visualize theoretical, reachable, and validated attack paths across your findings."
        icon={<Network className="h-6 w-6" />}
        actions={
          <Button size="sm" onClick={() => onNavigate("analyze")}>
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
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="flex-1">
                <label className="label">Application Context (optional)</label>
                <textarea
                  value={appContext}
                  onChange={(e) => setAppContext(e.target.value)}
                  placeholder="Describe your application architecture, entry points, trust boundaries..."
                  rows={3}
                  className="textarea"
                />
              </div>
              <Button onClick={runEngine} disabled={analyzing} size="lg">
                {analyzing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Network className="h-4 w-4" />}
                {analyzing ? "Reconstructing..." : "Generate Attack Paths"}
              </Button>
            </div>
            <p className="mt-2 text-xs text-ink-500">
              Analyzing {findings.length} findings to reconstruct attack paths
            </p>
          </Panel>

          {analyzing && (
            <Panel className="p-8 scanline">
              <div className="flex flex-col items-center text-center">
                <Loader2 className="h-8 w-8 animate-spin text-cyber-400" />
                <p className="mt-3 text-sm text-ink-300">Reconstructing attack paths...</p>
                <p className="mt-1 text-xs text-ink-500">Mapping entry points, data flows, and impact chains</p>
              </div>
            </Panel>
          )}

          {error && (
            <Panel className="p-4">
              <div className="flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            </Panel>
          )}

          {result && (
            <div className="space-y-4 animate-fade-in">
              {/* Paths */}
              {result.paths && result.paths.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-ink-100">Reconstructed Attack Paths</h3>
                  {result.paths.map((path, i) => (
                    <Panel key={i} className="p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyber-500/15 text-cyber-300 font-mono text-xs">
                            {i + 1}
                          </span>
                          <span className="text-sm font-semibold text-ink-100">{path.name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {path.classification && <ClassificationTag classification={path.classification} />}
                          <span
                            className={classNames(
                              "chip border",
                              path.status === "validated"
                                ? "text-danger bg-danger/15 border-danger/30"
                                : path.status === "reachable"
                                ? "text-orange-400 bg-orange-500/15 border-orange-500/30"
                                : "text-warning bg-warning/15 border-warning/30"
                            )}
                          >
                            {path.status}
                          </span>
                          <span className="text-xs text-ink-500 font-mono">{path.confidence}%</span>
                        </div>
                      </div>

                      {path.entry_point && (
                        <p className="mb-2 text-xs text-ink-400">
                          <span className="text-ink-500">Entry point:</span> {path.entry_point}
                        </p>
                      )}

                      {Array.isArray(path.steps) && path.steps.length > 0 && (
                        <div className="space-y-1.5">
                          {path.steps.map((step, j) => {
                            const stepObj = typeof step === "string" ? { action: step } : step as unknown as Record<string, unknown>;
                            return (
                              <div key={j} className="flex items-start gap-2 text-sm">
                                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-ink-800 font-mono text-[10px] text-ink-400">
                                  {j + 1}
                                </span>
                                <div className="flex-1">
                                  <span className="text-ink-200">{String(stepObj["action"] ?? stepObj["node"] ?? JSON.stringify(stepObj))}</span>
                                  {typeof stepObj["classification"] === "string" && (
                                    <ClassificationTag classification={stepObj["classification"] as never} className="ml-1.5" />
                                  )}
                                </div>
                                {j < path.steps.length - 1 && <ArrowRight className="h-3 w-3 text-ink-600 mt-1" />}
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {path.impact && (
                        <div className="mt-3 rounded-lg border border-danger/20 bg-danger/5 p-2">
                          <p className="text-xs font-semibold text-danger">Impact: {path.impact}</p>
                        </div>
                      )}

                      {path.prerequisites && path.prerequisites.length > 0 && (
                        <div className="mt-2">
                          <p className="text-[10px] uppercase tracking-wider text-ink-500 mb-1">Prerequisites</p>
                          <div className="flex flex-wrap gap-1.5">
                            {path.prerequisites.map((p, k) => (
                              <span key={k} className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400">
                                {p}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </Panel>
                  ))}
                </div>
              )}

              {/* Graph visualization */}
              {result.graph && result.graph.nodes && result.graph.nodes.length > 0 && (
                <Panel className="p-5">
                  <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
                    <GitBranch className="h-4 w-4 text-cyber-400" />
                    Security Graph
                  </h3>
                  <div className="overflow-x-auto">
                    <svg width="100%" height={Math.max(300, result.graph.nodes.length * 40)} className="min-w-[600px]">
                      {result.graph.nodes.map((node, i) => {
                        const cols = 4;
                        const col = i % cols;
                        const row = Math.floor(i / cols);
                        const x = 80 + col * 180;
                        const y = 40 + row * 80;
                        const typeColors: Record<string, string> = {
                          endpoint: "#ef4444",
                          function: "#f59e0b",
                          data_flow: "#0889b5",
                          cve: "#dc2626",
                          dependency: "#3366ff",
                          impact: "#ef4444",
                        };
                        return (
                          <g key={node.id}>
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
                              {node.label.length > 18 ? node.label.slice(0, 18) + "..." : node.label}
                            </text>
                            <text x={x + 110} y={y + 20} fill={typeColors[node.type] ?? "#5a6a85"} fontSize="8" fontFamily="monospace">
                              {node.type}
                            </text>
                          </g>
                        );
                      })}
                      {result.graph.edges.map((edge, i) => {
                        const fromNode = result.graph.nodes.find((n) => n.id === edge.from);
                        const toNode = result.graph.nodes.find((n) => n.id === edge.to);
                        if (!fromNode || !toNode) return null;
                        const fromIdx = result.graph.nodes.indexOf(fromNode);
                        const toIdx = result.graph.nodes.indexOf(toNode);
                        const cols = 4;
                        const fx = 80 + (fromIdx % cols) * 180 + 140;
                        const fy = 40 + Math.floor(fromIdx / cols) * 80 + 16;
                        const tx = 80 + (toIdx % cols) * 180;
                        const ty = 40 + Math.floor(toIdx / cols) * 80 + 16;
                        return (
                          <g key={i}>
                            <line x1={fx} y1={fy} x2={tx} y2={ty} stroke="#283449" strokeWidth={1} strokeDasharray="4 3" />
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-3 text-xs text-ink-400">
                    {["endpoint", "function", "data_flow", "cve", "dependency", "impact"].map((t) => (
                      <span key={t} className="flex items-center gap-1.5">
                        <span
                          className="h-2.5 w-2.5 rounded"
                          style={{
                            background: {
                              endpoint: "#ef4444",
                              function: "#f59e0b",
                              data_flow: "#0889b5",
                              cve: "#dc2626",
                              dependency: "#3366ff",
                              impact: "#ef4444",
                            }[t],
                          }}
                        />
                        {t}
                      </span>
                    ))}
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

import { useState, useEffect } from "react";
import { Radio, Loader2, AlertCircle, CheckCircle2, XCircle, HelpCircle, Activity } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { AIDastResult, RiskLevel } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  RiskBadge,
  SeverityBadge,
  ClassificationTag,
  EmptyState,
  StatCard,
  LedDot,
} from "@/components/ui-kit";
import { classNames } from "@/lib/utils";

const SAMPLE_EVIDENCE = `GET /api/profile?id=1042 HTTP/1.1
Host: staging.example.com
Cookie: session=eyJhbGciOi...

HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: Express
Content-Type: application/json
(no Strict-Transport-Security, no Content-Security-Policy, no X-Frame-Options)

{"id":1042,"email":"other.user@example.com","ssn":"***-**-4411","role":"admin"}

GET /api/profile?id=1043 -> 200 OK (returns a different user's record)
GET /api/../../etc/passwd -> 400
POST /api/login (12 attempts in 4s) -> 200, no lockout, no rate-limit headers`;

interface DastRunRow {
  id: string;
  target_url: string;
  summary: { risk?: RiskLevel; confirmed?: number; probes_run?: number } | null;
  created_at: string;
}

const VERDICT_ICON = {
  confirmed: <CheckCircle2 className="h-3.5 w-3.5 text-danger" />,
  refuted: <XCircle className="h-3.5 w-3.5 text-ok" />,
  inconclusive: <HelpCircle className="h-3.5 w-3.5 text-ink-400" />,
};

export function DastPage() {
  const [target, setTarget] = useState("");
  const [evidence, setEvidence] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIDastResult | null>(null);
  const [runs, setRuns] = useState<DastRunRow[]>([]);

  const loadRuns = async () => {
    const { data } = await supabase
      .from("dast_runs")
      .select("id, target_url, summary, created_at")
      .order("created_at", { ascending: false })
      .limit(15);
    setRuns((data as DastRunRow[]) ?? []);
  };

  useEffect(() => {
    void loadRuns();
  }, []);

  const handleRun = async () => {
    if (!target.trim()) {
      setError("Enter the target URL or environment you are testing.");
      return;
    }
    if (!evidence.trim()) {
      setError("Paste runtime evidence (headers, responses, or an HTTP transcript) so verdicts are grounded.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await ai.runDast(target, evidence);
      setResult(res);
      await supabase.from("dast_runs").insert({
        target_url: target,
        target_description: evidence.slice(0, 2000),
        status: "completed",
        probes: res.probes ?? [],
        findings: res.findings ?? [],
        summary: res.summary ?? null,
        runtime_notes: res.runtime_notes ?? null,
      } as never);
      await loadRuns();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="DAST / Runtime Testing"
        subtitle="Probe the running application and confirm — with runtime evidence — which vulnerabilities are real."
        icon={<Radio className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <label className="label">Target</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://staging.example.com"
              className="input w-full font-mono text-[13px]"
            />
            <div className="mb-2 mt-4 flex items-center justify-between">
              <label className="label !mb-0">Runtime evidence</label>
              <button
                onClick={() => {
                  setTarget(target || "https://staging.example.com");
                  setEvidence(SAMPLE_EVIDENCE);
                }}
                className="text-xs text-cyber-300 hover:text-cyber-200 transition-colors"
              >
                Load sample
              </button>
            </div>
            <textarea
              value={evidence}
              onChange={(e) => setEvidence(e.target.value)}
              spellCheck={false}
              placeholder="Paste response headers, HTTP transcripts, error pages, timing observations…"
              className="input h-72 w-full resize-y font-mono text-[13px]"
            />
            <Button onClick={handleRun} disabled={loading} className="mt-4 w-full">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" /> Running runtime probes…
                </span>
              ) : (
                "Run Runtime Tests"
              )}
            </Button>
            {error && (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/40 bg-danger/10 p-3 text-xs text-danger">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </Panel>

          <Panel className="p-5">
            <p className="stat-label mb-3">Recent runs</p>
            {runs.length === 0 ? (
              <p className="text-xs text-ink-500">No runtime tests yet.</p>
            ) : (
              <ul className="space-y-2">
                {runs.map((r) => (
                  <li key={r.id} className="flex items-center justify-between gap-2 text-xs">
                    <span className="truncate font-mono text-ink-300">{r.target_url}</span>
                    <span className="flex shrink-0 items-center gap-2">
                      <span className="text-ink-500">{r.summary?.confirmed ?? 0} confirmed</span>
                      <RiskBadge risk={(r.summary?.risk as RiskLevel) ?? "unknown"} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        <div className="lg:col-span-3 space-y-4">
          {!result && !loading && (
            <Panel className="p-10">
              <EmptyState
                icon={<Radio className="h-8 w-8" />}
                title="No runtime test yet"
                description="AegisCode designs runtime probes for your target and grades each one against the evidence you supply — confirmed, refuted, or inconclusive."
              />
            </Panel>
          )}

          {result && (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <StatCard label="Probes" value={result.summary?.probes_run ?? 0} accent="cyber" />
                <StatCard label="Confirmed" value={result.summary?.confirmed ?? 0} accent="danger" />
                <StatCard label="Refuted" value={result.summary?.refuted ?? 0} accent="volt" />
                <StatCard
                  label="Runtime risk"
                  value={<RiskBadge risk={result.summary?.risk ?? "unknown"} />}
                />
              </div>

              <Panel className="p-5">
                <p className="stat-label mb-3">Probe results</p>
                <ul className="space-y-2">
                  {(result.probes ?? []).map((p, i) => (
                    <li key={i} className="rounded-lg skeu-screen p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        {VERDICT_ICON[p.verdict] ?? VERDICT_ICON.inconclusive}
                        <span className="text-xs font-semibold text-ink-200">{p.name}</span>
                        <span className="text-[10px] uppercase tracking-wider text-ink-500">{p.category}</span>
                        {p.classification && <ClassificationTag classification={p.classification} />}
                      </div>
                      <pre className="mt-2 overflow-x-auto font-mono text-[11px] text-ink-300">{p.request}</pre>
                      <p className="mt-2 text-xs text-ink-400">
                        <span className="text-ink-500">Expected: </span>
                        {p.expected_signal}
                      </p>
                      <p className="text-xs text-ink-400">
                        <span className="text-ink-500">Observed: </span>
                        {p.observed_signal}
                      </p>
                    </li>
                  ))}
                </ul>
              </Panel>

              {(result.findings ?? []).map((f, i) => (
                <Panel key={i} className="p-5">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <h3 className="text-sm font-semibold text-ink-100">{f.title}</h3>
                    {f.cwe && <span className="font-mono text-[11px] text-ink-400">{f.cwe}</span>}
                    <span
                      className={classNames(
                        "flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                        f.confirmed_at_runtime ? "bg-danger/15 text-danger" : "bg-ink-800 text-ink-400",
                      )}
                    >
                      <LedDot color={f.confirmed_at_runtime ? "#ff4d4d" : "#5a6472"} />
                      {f.confirmed_at_runtime ? "Confirmed at runtime" : "Not confirmed"}
                    </span>
                    {typeof f.confidence === "number" && (
                      <span className="font-mono text-[11px] text-ink-400">
                        {Math.round(f.confidence * 100)}% confidence
                      </span>
                    )}
                  </div>

                  {(f.evidence ?? []).length > 0 && (
                    <div className="mt-3 space-y-2">
                      {(f.evidence ?? []).map((e, ei) => (
                        <div key={ei} className="rounded-lg skeu-screen p-3">
                          <div className="flex items-center gap-2">
                            <Activity className="h-3.5 w-3.5 text-cyber-300" />
                            <span className="text-[10px] uppercase tracking-wider text-ink-500">{e.type}</span>
                            {e.classification && <ClassificationTag classification={e.classification} />}
                          </div>
                          {e.snippet && (
                            <pre className="mt-2 overflow-x-auto font-mono text-[11px] text-ink-300">{e.snippet}</pre>
                          )}
                          {e.explanation && <p className="mt-2 text-xs text-ink-400">{e.explanation}</p>}
                        </div>
                      ))}
                    </div>
                  )}

                  {f.reproduction && (
                    <div className="mt-3">
                      <p className="stat-label mb-1">Reproduction</p>
                      <pre className="overflow-x-auto rounded-lg skeu-screen p-3 font-mono text-[11px] text-ink-300">
                        {f.reproduction}
                      </pre>
                    </div>
                  )}
                  {f.impact && <p className="mt-3 text-xs text-ink-300">{f.impact}</p>}
                  {f.remediation && <p className="mt-2 text-xs text-cyber-200">{f.remediation}</p>}
                </Panel>
              ))}

              {result.runtime_notes && (
                <Panel className="p-5">
                  <p className="stat-label mb-2">Runtime notes</p>
                  <p className="text-xs leading-relaxed text-ink-300">{result.runtime_notes}</p>
                </Panel>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

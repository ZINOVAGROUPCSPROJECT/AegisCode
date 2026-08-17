import { useEffect, useState } from "react";
import { Wrench, Loader2, AlertCircle, CheckCircle2, XCircle, ShieldCheck, Sparkles } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { Finding, Remediation, AIRemediationResult, AIVerificationResult } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  EmptyState,
  SeverityBadge,
  CodeBlock,
  ClassificationTag,
} from "@/components/ui-kit";
import { classNames, timeAgo } from "@/lib/utils";
import type { PageId } from "@/components/AppShell";

export function RemediationPage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [generating, setGenerating] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [fixResult, setFixResult] = useState<AIRemediationResult | null>(null);
  const [verifyResult, setVerifyResult] = useState<AIVerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const [{ data: f }, { data: r }] = await Promise.all([
        supabase.from("findings").select("*").order("created_at", { ascending: false }).limit(50),
        supabase.from("remediations").select("*").order("created_at", { ascending: false }).limit(20),
      ]);
      setFindings((f as Finding[]) ?? []);
      setRemediations((r as Remediation[]) ?? []);
      setLoading(false);
    })();
  }, []);

  const selected = findings.find((f) => f.id === selectedId);

  const generateFix = async () => {
    if (!selected) return;
    setGenerating(true);
    setError(null);
    setFixResult(null);
    setVerifyResult(null);
    try {
      const res = await ai.remediate(selected as unknown as Record<string, unknown>, code || selected.secure_fix || "No original code provided.");
      setFixResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setGenerating(false);
    }
  };

  const verifyFix = async () => {
    if (!selected || !fixResult) return;
    setVerifying(true);
    setError(null);
    try {
      const res = await ai.verifyRemediation(selected as unknown as Record<string, unknown>, fixResult.fix_code);
      setVerifyResult(res);

      await supabase.from("remediations").insert({
        finding_id: selected.id,
        fix_code: fixResult.fix_code,
        fix_description: fixResult.fix_description,
        verification_status: res.verification_status,
        verification_result: res as unknown as Record<string, unknown>,
      });

      if (res.verification_status === "verified") {
        await supabase.from("findings").update({ status: "verified", verified_gone: true }).eq("id", selected.id);
      } else {
        await supabase.from("findings").update({ status: "remediated" }).eq("id", selected.id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifying(false);
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
        title="Remediation & Verification"
        subtitle="Generate secure fixes and independently verify that the vulnerability and attack path are gone."
        icon={<Wrench className="h-6 w-6" />}
        actions={
          <Button size="sm" onClick={() => onNavigate("analyze")}>
            New Analysis
          </Button>
        }
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2 space-y-3">
          <Panel className="p-4">
            <h3 className="mb-3 text-sm font-semibold text-ink-100">Select a Finding to Remediate</h3>
            {findings.length === 0 ? (
              <EmptyState
                icon={<Wrench className="h-10 w-10" />}
                title="No findings available"
                description="Run a code analysis first to generate findings for remediation."
              />
            ) : (
              <div className="max-h-[400px] space-y-2 overflow-y-auto">
                {findings.map((f) => (
                  <div
                    key={f.id}
                    onClick={() => {
                      setSelectedId(f.id);
                      setFixResult(null);
                      setVerifyResult(null);
                      setError(null);
                    }}
                    className={classNames(
                      "rounded-lg border p-3 cursor-pointer transition-colors",
                      selectedId === f.id
                        ? "border-cyber-500/40 bg-cyber-500/10"
                        : "border-ink-700/40 bg-ink-850/50 hover:border-ink-600/60 hover:bg-ink-800/50"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={f.severity} />
                      {f.verified_gone && (
                        <span className="chip border border-volt-500/25 bg-volt-500/10 text-volt-300 text-[10px]">
                          <CheckCircle2 className="h-3 w-3" /> Verified
                        </span>
                      )}
                    </div>
                    <p className="text-sm font-medium text-ink-100 truncate">{f.title}</p>
                    <p className="text-xs text-ink-500 truncate">{f.cwe || f.location || "—"}</p>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {selected && (
            <Panel className="p-4">
              <label className="label">Original Code (optional)</label>
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="Paste the original vulnerable code to generate a fix..."
                rows={6}
                className="textarea"
              />
              <Button onClick={generateFix} disabled={generating} className="mt-3 w-full">
                {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                {generating ? "Generating Fix..." : "Generate Secure Fix"}
              </Button>
            </Panel>
          )}
        </div>

        <div className="lg:col-span-3 space-y-4">
          {(generating || verifying) && (
            <Panel className="p-8 scanline">
              <div className="flex flex-col items-center text-center">
                <Loader2 className="h-8 w-8 animate-spin text-cyber-400" />
                <p className="mt-3 text-sm text-ink-300">
                  {generating ? "Generating secure fix..." : "Independently verifying remediation..."}
                </p>
              </div>
            </Panel>
          )}

          {!generating && !verifying && !fixResult && !error && (
            <Panel className="p-8">
              <EmptyState
                icon={<Wrench className="h-12 w-12" />}
                title="No Remediation Yet"
                description="Select a finding and generate a secure fix. Then independently verify that the vulnerability is gone."
              />
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

          {fixResult && (
            <Panel className="p-5 space-y-4 animate-fade-in">
              <h3 className="text-sm font-semibold text-ink-100 flex items-center gap-2">
                <Wrench className="h-4 w-4 text-cyber-400" /> Generated Fix
              </h3>

              {fixResult.fix_description && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1">Description</p>
                  <p className="text-sm text-ink-300">{fixResult.fix_description}</p>
                </div>
              )}

              {fixResult.fix_code && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Fixed Code</p>
                  <CodeBlock code={fixResult.fix_code} />
                </div>
              )}

              {fixResult.changes && fixResult.changes.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Changes</p>
                  <div className="space-y-1.5">
                    {fixResult.changes.map((c, i) => (
                      <div key={i} className="rounded border border-ink-700/40 bg-ink-850/50 p-2 text-xs">
                        <span className="font-mono text-cyber-300">{c.file}</span>
                        <p className="mt-0.5 text-ink-300">{c.change}</p>
                        <p className="mt-0.5 text-ink-500">{c.reason}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {fixResult.verification_steps && fixResult.verification_steps.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Verification Steps</p>
                  <ul className="space-y-1">
                    {fixResult.verification_steps.map((s, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-ink-300">
                        <span className="font-mono text-ink-600 mt-0.5">{i + 1}.</span>
                        {s}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {fixResult.residual_risk && (
                <div className="rounded-lg border border-warning/20 bg-warning/5 p-3">
                  <p className="text-xs font-semibold text-warning">Residual Risk: {fixResult.residual_risk}</p>
                </div>
              )}

              <Button onClick={verifyFix} disabled={verifying} className="w-full">
                {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                {verifying ? "Verifying..." : "Independently Verify Fix"}
              </Button>
            </Panel>
          )}

          {verifyResult && (
            <Panel className="p-5 space-y-4 animate-fade-in">
              <div className="flex items-center gap-3">
                {verifyResult.verification_status === "verified" ? (
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-volt-500/15 text-volt-300">
                    <CheckCircle2 className="h-6 w-6" />
                  </div>
                ) : verifyResult.verification_status === "failed" ? (
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-danger/15 text-danger">
                    <XCircle className="h-6 w-6" />
                  </div>
                ) : (
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-ink-700/40 text-ink-400">
                    <AlertCircle className="h-6 w-6" />
                  </div>
                )}
                <div>
                  <p className="text-lg font-bold text-ink-100 capitalize">{verifyResult.verification_status}</p>
                  <p className="text-xs text-ink-500 font-mono">{verifyResult.confidence}% confidence</p>
                </div>
              </div>

              {verifyResult.verdict && (
                <div className="rounded-lg border border-ink-700/40 bg-ink-950/40 p-3">
                  <p className="text-sm text-ink-200">{verifyResult.verdict}</p>
                </div>
              )}

              {verifyResult.checks && verifyResult.checks.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Verification Checks</p>
                  <div className="space-y-1.5">
                    {verifyResult.checks.map((c, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm">
                        {c.passed ? (
                          <CheckCircle2 className="h-4 w-4 text-volt-400 mt-0.5 shrink-0" />
                        ) : (
                          <XCircle className="h-4 w-4 text-danger mt-0.5 shrink-0" />
                        )}
                        <div className="flex-1">
                          <span className="text-ink-200">{c.check}</span>
                          {c.classification && <ClassificationTag classification={c.classification} className="ml-1.5" />}
                          <p className="text-xs text-ink-400 mt-0.5">{c.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {verifyResult.residual_issues && verifyResult.residual_issues.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Residual Issues</p>
                  <ul className="space-y-1">
                    {verifyResult.residual_issues.map((r, i) => (
                      <li key={i} className="text-xs text-warning flex items-start gap-1.5">
                        <AlertCircle className="h-3 w-3 mt-0.5 shrink-0" />
                        {r}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </Panel>
          )}

          {remediations.length > 0 && !fixResult && (
            <Panel className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-ink-100">Recent Remediations</h3>
              <div className="space-y-2">
                {remediations.slice(0, 6).map((r) => (
                  <div key={r.id} className="flex items-center justify-between rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                    <div>
                      <p className="text-xs text-ink-400">Finding: {r.finding_id.slice(0, 8)}...</p>
                      <p className="text-[10px] text-ink-500">{timeAgo(r.created_at)}</p>
                    </div>
                    <span
                      className={classNames(
                        "chip border",
                        r.verification_status === "verified"
                          ? "text-volt-300 bg-volt-500/10 border-volt-500/25"
                          : r.verification_status === "failed"
                          ? "text-danger bg-danger/15 border-danger/30"
                          : "text-warning bg-warning/10 border-warning/20"
                      )}
                    >
                      {r.verification_status}
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

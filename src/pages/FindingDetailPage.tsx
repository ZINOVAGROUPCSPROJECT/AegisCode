import { useState, useEffect, useMemo } from "react";
import {
  Bug,
  Loader2,
  ArrowLeft,
  Crosshair,
  Wrench,
  ShieldCheck,
  Gauge,
  Network,
  Code2,
  ExternalLink,
  CheckCircle2,
} from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type {
  Finding,
  AIExploitabilityResult,
  AIRemediationResult,
  AIVerificationResult,
} from "@/lib/types";
import type { PageId } from "@/components/AppShell";
import {
  Panel,
  PageHeader,
  Button,
  SeverityBadge,
  ExploitabilityBadge,
  ClassificationTag,
  RiskBadge,
  CvssScore,
  EpssScore,
  KevBadge,
  EmptyState,
  CodeBlock,
} from "@/components/ui-kit";
import { classNames, aegisRiskScore, type ExposureLevel, type AssetImportance } from "@/lib/utils";

const STORAGE_KEY = "aegis.finding";

export function FindingDetailPage({ onNavigate }: { onNavigate?: (page: PageId) => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [id, setId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [exposure, setExposure] = useState<ExposureLevel>("internet");
  const [asset, setAsset] = useState<AssetImportance>("high");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exploit, setExploit] = useState<AIExploitabilityResult | null>(null);
  const [fix, setFix] = useState<AIRemediationResult | null>(null);
  const [verification, setVerification] = useState<AIVerificationResult | null>(null);

  useEffect(() => {
    (async () => {
      const { data } = await supabase
        .from("findings")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);
      const rows = (data as Finding[]) ?? [];
      setFindings(rows);
      const stored = window.sessionStorage.getItem(STORAGE_KEY);
      setId(stored && rows.some((r) => r.id === stored) ? stored : (rows[0]?.id ?? null));
      setLoading(false);
    })();
  }, []);

  const finding = useMemo(() => findings.find((f) => f.id === id) ?? null, [findings, id]);

  const select = (next: string) => {
    window.sessionStorage.setItem(STORAGE_KEY, next);
    setId(next);
    setExploit(null);
    setFix(null);
    setVerification(null);
  };

  const risk = useMemo(() => {
    if (!finding) return null;
    return aegisRiskScore({
      severity: finding.severity,
      exploitability: exploit?.exploitability ?? finding.exploitability,
      cvss_score: finding.cvss_score,
      epss_score: finding.epss_score,
      in_kev: finding.in_kev,
      exposure,
      asset_importance: asset,
    });
  }, [finding, exploit, exposure, asset]);

  useEffect(() => {
    if (!finding || !risk) return;
    void supabase
      .from("findings")
      .update({ aegis_risk_score: risk.score, aegis_risk_factors: risk.factors } as never)
      .eq("id", finding.id);
  }, [finding?.id, risk?.score]);

  const findingPayload = (f: Finding) => ({
    title: f.title,
    description: f.description,
    severity: f.severity,
    cwe: f.cwe,
    cvss_score: f.cvss_score,
    location: f.location,
    file_path: f.file_path,
    line_start: f.line_start,
    evidence: f.evidence,
    data_flow: f.data_flow,
  });

  const run = async (kind: "exploit" | "fix" | "verify") => {
    if (!finding) return;
    setBusy(kind);
    setError(null);
    try {
      if (kind === "exploit") {
        const res = await ai.assessExploitability(
          findingPayload(finding),
          `Exposure: ${exposure}. Asset importance: ${asset}. Location: ${finding.file_path || finding.location || "unknown"}.`,
        );
        setExploit(res);
        await supabase
          .from("findings")
          .update({
            exploitability: res.exploitability,
            exploit_confidence: res.confidence ?? finding.exploit_confidence,
            reachability: res.classification ?? finding.reachability,
            verdict: { reasoning: res.reasoning, confidence: res.confidence, classification: res.classification },
          } as never)
          .eq("id", finding.id);
      } else if (kind === "fix") {
        const code =
          (finding.evidence ?? []).map((e) => e.snippet).filter(Boolean).join("\n\n") ||
          finding.description ||
          finding.title;
        const res = await ai.remediate(findingPayload(finding), code);
        setFix(res);
        await supabase
          .from("findings")
          .update({ secure_fix: res.fix_code ?? null, remediation: res.fix_description ?? finding.remediation } as never)
          .eq("id", finding.id);
        await supabase.from("remediations").insert({
          finding_id: finding.id,
          fix_code: res.fix_code ?? null,
          fix_description: res.fix_description ?? null,
          verification_status: "pending",
        } as never);
      } else {
        const fixedCode = fix?.fix_code || finding.secure_fix;
        if (!fixedCode) {
          setError("Generate a fix first — verification needs the remediated code.");
          setBusy(null);
          return;
        }
        const res = await ai.verifyRemediation(findingPayload(finding), fixedCode);
        setVerification(res);
        await supabase
          .from("findings")
          .update({
            verified_gone: res.verification_status === "verified",
            status: res.verification_status === "verified" ? "fixed" : finding.status,
          } as never)
          .eq("id", finding.id);
      }
      const { data } = await supabase.from("findings").select("*").eq("id", finding.id).single();
      if (data) setFindings((prev) => prev.map((f) => (f.id === finding.id ? (data as Finding) : f)));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  if (loading) {
    return (
      <Panel className="flex items-center justify-center p-16">
        <Loader2 className="h-6 w-6 animate-spin text-cyber-400" />
      </Panel>
    );
  }

  if (!finding) {
    return (
      <div className="space-y-6 animate-fade-in">
        <PageHeader title="Finding Details" icon={<Bug className="h-6 w-6" />} />
        <Panel className="p-10">
          <EmptyState
            icon={<Bug className="h-8 w-8" />}
            title="No findings yet"
            description="Run a code analysis to populate findings, then open one here for the full picture."
            action={onNavigate ? <Button onClick={() => onNavigate("analyze")}>Analyze code</Button> : undefined}
          />
        </Panel>
      </div>
    );
  }

  const attackPaths = finding.attack_paths ?? [];

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title={finding.title}
        subtitle={`${finding.cwe || "no CWE"} · ${finding.file_path || finding.location || "unknown location"}${
          finding.line_start ? `:${finding.line_start}` : ""
        }`}
        icon={<Bug className="h-6 w-6" />}
        actions={
          onNavigate ? (
            <Button variant="ghost" size="sm" onClick={() => onNavigate("code-security")}>
              <span className="flex items-center gap-1.5">
                <ArrowLeft className="h-3 w-3" /> All findings
              </span>
            </Button>
          ) : undefined
        }
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-2">
          <Panel className="p-4">
            <p className="stat-label mb-3">Findings</p>
            <ul className="max-h-72 space-y-2 overflow-y-auto pr-1">
              {findings.map((f) => (
                <li key={f.id}>
                  <button
                    onClick={() => select(f.id)}
                    className={classNames(
                      "w-full rounded-lg skeu-screen p-3 text-left",
                      f.id === finding.id && "ring-1 ring-cyber-500/40",
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="min-w-0 truncate text-xs text-ink-200">{f.title}</span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel className="p-5">
            <div className="mb-3 flex items-center gap-2">
              <Gauge className="h-4 w-4 text-cyber-300" />
              <p className="stat-label !mb-0">Aegis Risk Score</p>
            </div>
            <div className="flex items-end gap-3">
              <span className="font-mono text-4xl font-bold text-ink-100">{risk?.score ?? 0}</span>
              <span className="mb-1">
                <RiskBadge risk={risk?.band ?? "unknown"} />
              </span>
            </div>
            <div className="mt-4 space-y-2">
              {(risk?.factors ?? []).map((f) => (
                <div key={f.label}>
                  <div className="flex items-center justify-between text-[11px] text-ink-400">
                    <span>{f.label}</span>
                    <span className="font-mono">+{f.contribution}</span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-ink-800">
                    <div
                      className="h-full rounded-full bg-cyber-400"
                      style={{ width: `${Math.min(f.value * 100, 100)}%` }}
                    />
                  </div>
                  <p className="mt-1 text-[10px] text-ink-500">{f.detail}</p>
                </div>
              ))}
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2">
              <div>
                <label className="label">Exposure</label>
                <select
                  value={exposure}
                  onChange={(e) => setExposure(e.target.value as ExposureLevel)}
                  className="input w-full py-1 text-[12px]"
                >
                  <option value="internet">internet</option>
                  <option value="authenticated">authenticated</option>
                  <option value="internal">internal</option>
                  <option value="unknown">unknown</option>
                </select>
              </div>
              <div>
                <label className="label">Asset importance</label>
                <select
                  value={asset}
                  onChange={(e) => setAsset(e.target.value as AssetImportance)}
                  className="input w-full py-1 text-[12px]"
                >
                  <option value="crown_jewel">crown jewel</option>
                  <option value="high">high</option>
                  <option value="standard">standard</option>
                  <option value="low">low</option>
                  <option value="unknown">unknown</option>
                </select>
              </div>
            </div>
          </Panel>

          <Panel className="p-5">
            <p className="stat-label mb-3">Actions</p>
            <div className="space-y-2">
              <Button className="w-full" onClick={() => void run("exploit")} disabled={busy !== null}>
                <span className="flex items-center justify-center gap-2">
                  {busy === "exploit" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />}
                  Prove exploitability
                </span>
              </Button>
              <Button className="w-full" variant="ghost" onClick={() => void run("fix")} disabled={busy !== null}>
                <span className="flex items-center justify-center gap-2">
                  {busy === "fix" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}
                  Generate AI patch
                </span>
              </Button>
              <Button className="w-full" variant="ghost" onClick={() => void run("verify")} disabled={busy !== null}>
                <span className="flex items-center justify-center gap-2">
                  {busy === "verify" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                  Verify the fix
                </span>
              </Button>
            </div>
            {error && <p className="mt-3 text-xs text-danger">{error}</p>}
          </Panel>
        </div>

        <div className="space-y-4 lg:col-span-3">
          <Panel className="p-5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ExploitabilityBadge exploitability={exploit?.exploitability ?? finding.exploitability} />
              <ClassificationTag classification={exploit?.classification ?? finding.reachability} />
              <KevBadge inKev={finding.in_kev} />
              {finding.verified_gone && (
                <span className="flex items-center gap-1 rounded bg-ok/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-ok">
                  <CheckCircle2 className="h-3 w-3" /> Verified fixed
                </span>
              )}
            </div>
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <div>
                <p className="stat-label">CVSS</p>
                <CvssScore score={finding.cvss_score} />
                {finding.cvss_vector && (
                  <p className="mt-1 font-mono text-[10px] text-ink-500">{finding.cvss_vector}</p>
                )}
              </div>
              <div>
                <p className="stat-label">EPSS</p>
                <EpssScore score={finding.epss_score} percentile={finding.epss_percentile} />
              </div>
              <div>
                <p className="stat-label">CWE</p>
                {finding.cwe ? (
                  <a
                    href={finding.cwe_url || `https://cwe.mitre.org/data/definitions/${finding.cwe.replace(/\D/g, "")}.html`}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 font-mono text-sm text-cyber-300 hover:text-cyber-200"
                  >
                    {finding.cwe} <ExternalLink className="h-3 w-3" />
                  </a>
                ) : (
                  <p className="text-sm text-ink-400">—</p>
                )}
              </div>
            </div>
            {finding.description && (
              <p className="mt-4 text-sm leading-relaxed text-ink-300">{finding.description}</p>
            )}
          </Panel>

          {(exploit || finding.verdict?.reasoning) && (
            <Panel className="p-5">
              <div className="mb-3 flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-cyber-300" />
                <p className="stat-label !mb-0">Exploitability verdict</p>
              </div>
              <p className="text-xs leading-relaxed text-ink-300">
                {exploit?.reasoning || finding.verdict?.reasoning}
              </p>
              {(exploit?.reachability_chain ?? []).map((n, i) => (
                <div key={i} className="mt-3 rounded-lg skeu-screen p-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] text-ink-500">#{n.step ?? i + 1}</span>
                    <span className="text-xs font-semibold text-ink-200">{n.point}</span>
                    <span
                      className={classNames(
                        "rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                        n.reachable ? "bg-danger/15 text-danger" : "bg-ok/15 text-ok",
                      )}
                    >
                      {n.reachable ? "reachable" : "blocked"}
                    </span>
                    {n.classification && <ClassificationTag classification={n.classification} />}
                  </div>
                </div>
              ))}
              {(exploit?.conditions_required ?? []).length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-ink-400">
                  {(exploit?.conditions_required ?? []).map((c, i) => (
                    <li key={i}>• {c}</li>
                  ))}
                </ul>
              )}
            </Panel>
          )}

          {(finding.evidence ?? []).length > 0 && (
            <Panel className="p-5">
              <div className="mb-3 flex items-center gap-2">
                <Code2 className="h-4 w-4 text-cyber-300" />
                <p className="stat-label !mb-0">Evidence</p>
              </div>
              <div className="space-y-3">
                {(finding.evidence ?? []).map((e, i) => (
                  <div key={i}>
                    <div className="mb-1 flex items-center gap-2">
                      <span className="text-[10px] uppercase tracking-wider text-ink-500">{e.type || "evidence"}</span>
                      {e.classification && <ClassificationTag classification={e.classification} />}
                    </div>
                    {e.snippet && <CodeBlock code={e.snippet} />}
                    {e.explanation && <p className="mt-2 text-xs text-ink-400">{e.explanation}</p>}
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {(finding.data_flow ?? []).length > 0 && (
            <Panel className="p-5">
              <p className="stat-label mb-3">Data flow</p>
              <ol className="space-y-2">
                {(finding.data_flow ?? []).map((n, i) => (
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
            </Panel>
          )}

          {attackPaths.length > 0 && (
            <Panel className="p-5">
              <div className="mb-3 flex items-center gap-2">
                <Network className="h-4 w-4 text-cyber-300" />
                <p className="stat-label !mb-0">Attack paths</p>
              </div>
              <div className="space-y-3">
                {attackPaths.map((p, i) => (
                  <div key={p.id || i} className="rounded-lg skeu-screen p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-semibold text-ink-200">{p.name}</span>
                      <span className="text-[10px] uppercase tracking-wider text-ink-500">{p.status}</span>
                      <span className="font-mono text-[11px] text-ink-400">
                        {Math.round((p.confidence ?? 0) * 100)}%
                      </span>
                      {p.classification && <ClassificationTag classification={p.classification} />}
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-300">
                      {(p.steps ?? []).map((s, si) => {
                        const label = typeof s === "string" ? s : `${s.node} — ${s.action}`;
                        return (
                          <span key={si} className="flex items-center gap-1.5">
                            <span className="rounded skeu-bezel px-2 py-0.5">{label}</span>
                            {si < (p.steps ?? []).length - 1 && <span className="text-ink-600">→</span>}
                          </span>
                        );
                      })}
                    </div>
                    {p.impact && <p className="mt-2 text-xs text-ink-400">{p.impact}</p>}
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {(fix || finding.secure_fix) && (
            <Panel className="p-5">
              <div className="mb-3 flex items-center gap-2">
                <Wrench className="h-4 w-4 text-cyber-300" />
                <p className="stat-label !mb-0">AI remediation</p>
              </div>
              {fix?.fix_description && (
                <p className="mb-3 text-xs leading-relaxed text-ink-300">{fix.fix_description}</p>
              )}
              {(fix?.fix_code || finding.secure_fix) && (
                <div className="mt-3">
                  <p className="stat-label mb-1">Patched code</p>
                  <CodeBlock code={(fix?.fix_code || finding.secure_fix) as string} />
                </div>
              )}
              {(fix?.changes ?? []).length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-ink-400">
                  {(fix?.changes ?? []).map((c, i) => (
                    <li key={i}>
                      <span className="font-mono text-ink-300">{c.file}</span> — {c.change} ({c.reason})
                    </li>
                  ))}
                </ul>
              )}
              {fix?.residual_risk && <p className="mt-3 text-xs text-warning">{fix.residual_risk}</p>}
            </Panel>
          )}

          {verification && (
            <Panel className="p-5">
              <div className="mb-3 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-cyber-300" />
                <p className="stat-label !mb-0">Fix verification</p>
              </div>
              <div
                className={classNames(
                  "rounded-lg p-3 text-xs",
                  verification.verification_status === "verified"
                    ? "bg-ok/10 text-ok"
                    : "bg-danger/10 text-danger",
                )}
              >
                {verification.verification_status === "verified"
                  ? "Independently verified: the vulnerability is gone."
                  : "Not verified: the vulnerability or an equivalent path still appears reachable."}
              </div>
              {verification.verdict && (
                <p className="mt-3 text-xs leading-relaxed text-ink-300">{verification.verdict}</p>
              )}
              {(verification.residual_issues ?? []).length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-ink-400">
                  {(verification.residual_issues ?? []).map((r, i) => (
                    <li key={i}>• {r}</li>
                  ))}
                </ul>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

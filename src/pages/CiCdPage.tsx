import { useState, useEffect } from "react";
import {
  GitBranch,
  Loader2,
  AlertCircle,
  ShieldBan,
  ShieldCheck,
  ShieldAlert,
  Github,
  Plus,
  Trash2,
} from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { AIPrGateResult, GateStatus, RiskLevel, Severity } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  RiskBadge,
  SeverityBadge,
  ClassificationTag,
  EmptyState,
  StatCard,
  Toggle,
  CodeBlock,
} from "@/components/ui-kit";
import { classNames } from "@/lib/utils";

const SAMPLE_DIFF = `diff --git a/src/routes/report.ts b/src/routes/report.ts
@@ -12,6 +12,12 @@
+router.get('/report', async (req, res) => {
+  const rows = await db.raw(
+    \`SELECT * FROM reports WHERE owner = '\${req.query.owner}'\`
+  );
+  res.json(rows);
+});
diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml
@@
+      - run: curl -H "Authorization: Bearer sk_live_51H9x8kLmNoPq" https://api.example.com/deploy`;

interface Integration {
  id: string;
  provider: string;
  repository: string;
  default_branch: string;
  scan_pull_requests: boolean;
  block_on_severity: Severity;
  block_on_exploitable: boolean;
  block_on_secrets: boolean;
  enabled: boolean;
}

interface PrScanRow {
  id: string;
  title: string;
  author: string | null;
  branch: string | null;
  pr_number: number | null;
  gate_status: GateStatus;
  blocking_reasons: string[];
  summary: { risk?: RiskLevel; introduced?: number } | null;
  created_at: string;
}

const GATE_STYLE: Record<GateStatus, { cls: string; icon: typeof ShieldBan; label: string }> = {
  blocked: { cls: "bg-danger/15 text-danger", icon: ShieldBan, label: "Deployment blocked" },
  warning: { cls: "bg-warning/15 text-warning", icon: ShieldAlert, label: "Warning" },
  passed: { cls: "bg-ok/15 text-ok", icon: ShieldCheck, label: "Gate passed" },
};

export function CiCdPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [provider, setProvider] = useState("github");
  const [repository, setRepository] = useState("");
  const [selected, setSelected] = useState<string>("");
  const [prTitle, setPrTitle] = useState("");
  const [prNumber, setPrNumber] = useState("");
  const [author, setAuthor] = useState("");
  const [branch, setBranch] = useState("");
  const [diff, setDiff] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIPrGateResult | null>(null);
  const [scans, setScans] = useState<PrScanRow[]>([]);

  const load = async () => {
    const [{ data: ints }, { data: prs }] = await Promise.all([
      supabase.from("ci_integrations").select("*").order("created_at", { ascending: false }),
      supabase
        .from("pr_scans")
        .select("id, title, author, branch, pr_number, gate_status, blocking_reasons, summary, created_at")
        .order("created_at", { ascending: false })
        .limit(20),
    ]);
    const list = (ints as Integration[]) ?? [];
    setIntegrations(list);
    setScans((prs as PrScanRow[]) ?? []);
    setSelected((prev) => prev || list[0]?.id || "");
  };

  useEffect(() => {
    void load();
  }, []);

  const addIntegration = async () => {
    if (!repository.trim()) {
      setError("Enter a repository, e.g. acme/payments-api.");
      return;
    }
    setError(null);
    const { error: insertError } = await supabase
      .from("ci_integrations")
      .insert({ provider, repository: repository.trim() } as never);
    if (insertError) setError(insertError.message);
    setRepository("");
    await load();
  };

  const patch = async (id: string, values: Record<string, unknown>) => {
    await supabase.from("ci_integrations").update(values as never).eq("id", id);
    await load();
  };

  const removeIntegration = async (id: string) => {
    await supabase.from("ci_integrations").delete().eq("id", id);
    await load();
  };

  const active = integrations.find((i) => i.id === selected) ?? null;

  const runGate = async () => {
    if (!diff.trim()) {
      setError("Paste the pull-request diff to review.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const policy = active
        ? `Repository: ${active.repository} (${active.provider}), default branch ${active.default_branch}.
Block when any finding is severity ${active.block_on_severity} or above.
Block on proven-exploitable findings: ${active.block_on_exploitable ? "yes" : "no"}.
Block when a secret is introduced: ${active.block_on_secrets ? "yes" : "no"}.`
        : "Block when any finding is severity high or above, when a finding is proven exploitable, or when a secret is introduced.";

      const res = await ai.gatePullRequest(
        {
          title: prTitle || "Untitled pull request",
          author,
          branch,
          diff,
        },
        policy,
      );
      setResult(res);
      await supabase.from("pr_scans").insert({
        integration_id: active?.id ?? null,
        pr_number: prNumber ? Number(prNumber) : null,
        title: prTitle || "Untitled pull request",
        author: author || null,
        branch: branch || null,
        diff_summary: diff.slice(0, 4000),
        gate_status: res.gate_status ?? "passed",
        blocking_reasons: res.blocking_reasons ?? [],
        findings: res.findings ?? [],
        summary: res.summary ?? null,
      } as never);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const gate = result ? (GATE_STYLE[result.gate_status] ?? GATE_STYLE.passed) : null;
  const GateIcon = gate?.icon ?? ShieldCheck;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="CI/CD — GitHub & GitLab"
        subtitle="Scan pull requests and block deployments when dangerous vulnerabilities appear."
        icon={<GitBranch className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <p className="stat-label mb-3">Connected repositories</p>
            <div className="flex gap-2">
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="input w-28 text-[13px]"
              >
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
              </select>
              <input
                value={repository}
                onChange={(e) => setRepository(e.target.value)}
                placeholder="acme/payments-api"
                className="input min-w-0 flex-1 font-mono text-[13px]"
              />
              <Button size="sm" onClick={addIntegration}>
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            <ul className="mt-4 space-y-3">
              {integrations.map((i) => (
                <li
                  key={i.id}
                  className={classNames(
                    "rounded-lg skeu-screen p-3",
                    selected === i.id && "ring-1 ring-cyber-500/40",
                  )}
                >
                  <button
                    onClick={() => setSelected(i.id)}
                    className="flex w-full items-center justify-between gap-2 text-left"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <Github className="h-3.5 w-3.5 text-ink-400" />
                      <span className="truncate font-mono text-xs text-ink-200">{i.repository}</span>
                    </span>
                    <span className="text-[10px] uppercase tracking-wider text-ink-500">{i.provider}</span>
                  </button>
                  <div className="mt-3 space-y-2 text-xs text-ink-400">
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 pr-1">Scan pull requests</span>
                      <Toggle
                        label="Scan pull requests"
                        checked={i.scan_pull_requests}
                        onChange={(v) => void patch(i.id, { scan_pull_requests: v })}
                      />
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 pr-1">Block on exploitable</span>
                      <Toggle
                        label="Block on exploitable"
                        checked={i.block_on_exploitable}
                        onChange={(v) => void patch(i.id, { block_on_exploitable: v })}
                      />
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 pr-1">Block on secrets</span>
                      <Toggle
                        label="Block on secrets"
                        checked={i.block_on_secrets}
                        onChange={(v) => void patch(i.id, { block_on_secrets: v })}
                      />
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 pr-1">Block at severity</span>
                      <select
                        value={i.block_on_severity}
                        onChange={(e) => void patch(i.id, { block_on_severity: e.target.value })}
                        className="input w-auto min-w-24 shrink-0 py-1 text-[12px]"
                      >
                        <option value="critical">critical</option>
                        <option value="high">high</option>
                        <option value="medium">medium</option>
                        <option value="low">low</option>
                      </select>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 pr-1">Enabled</span>
                      <Toggle label="Enabled" checked={i.enabled} onChange={(v) => void patch(i.id, { enabled: v })} />
                    </div>
                    <button
                      onClick={() => void removeIntegration(i.id)}
                      className="flex items-center gap-1.5 text-[11px] text-danger hover:opacity-80"
                    >
                      <Trash2 className="h-3 w-3" /> Disconnect
                    </button>
                  </div>
                </li>
              ))}
              {integrations.length === 0 && (
                <li className="text-xs text-ink-500">No repositories connected yet.</li>
              )}
            </ul>
          </Panel>

          <Panel className="p-5">
            <p className="stat-label mb-3">Pull request</p>
            <input
              value={prTitle}
              onChange={(e) => setPrTitle(e.target.value)}
              placeholder="Add report export endpoint"
              className="input mb-2 w-full text-[13px]"
            />
            <div className="mb-2 flex gap-2">
              <input
                value={prNumber}
                onChange={(e) => setPrNumber(e.target.value)}
                placeholder="#PR"
                className="input w-24 font-mono text-[13px]"
              />
              <input
                value={author}
                onChange={(e) => setAuthor(e.target.value)}
                placeholder="author"
                className="input min-w-0 flex-1 text-[13px]"
              />
              <input
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="branch"
                className="input min-w-0 flex-1 font-mono text-[13px]"
              />
            </div>
            <div className="mb-2 flex items-center justify-between">
              <label className="label !mb-0">Diff</label>
              <button
                onClick={() => {
                  setPrTitle(prTitle || "Add report export endpoint");
                  setBranch(branch || "feat/report-export");
                  setDiff(SAMPLE_DIFF);
                }}
                className="text-xs text-cyber-300 hover:text-cyber-200 transition-colors"
              >
                Load sample
              </button>
            </div>
            <textarea
              value={diff}
              onChange={(e) => setDiff(e.target.value)}
              spellCheck={false}
              placeholder="Paste the unified diff for the pull request…"
              className="input h-56 w-full resize-y font-mono text-[13px]"
            />
            <Button onClick={runGate} disabled={loading} className="mt-4 w-full">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" /> Reviewing pull request…
                </span>
              ) : (
                "Run CI/CD Gate"
              )}
            </Button>
            {error && (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/40 bg-danger/10 p-3 text-xs text-danger">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </Panel>
        </div>

        <div className="lg:col-span-3 space-y-4">
          {!result && !loading && (
            <Panel className="p-10">
              <EmptyState
                icon={<GitBranch className="h-8 w-8" />}
                title="No pull request reviewed yet"
                description="Connect a repository, set the blocking policy, then run the gate on a diff. AegisCode reports introduced versus resolved risk and decides whether the deployment is blocked."
              />
            </Panel>
          )}

          {result && gate && (
            <>
              <Panel className="p-5">
                <div className={classNames("flex items-center gap-3 rounded-lg p-4", gate.cls)}>
                  <GateIcon className="h-6 w-6" />
                  <div>
                    <p className="text-sm font-bold uppercase tracking-wider">{gate.label}</p>
                    <p className="text-xs opacity-80">
                      {result.summary?.introduced ?? 0} introduced · {result.summary?.resolved ?? 0} resolved ·{" "}
                      {result.summary?.files_changed ?? 0} files changed
                    </p>
                  </div>
                  <span className="ml-auto">
                    <RiskBadge risk={result.summary?.risk ?? "unknown"} />
                  </span>
                </div>

                {(result.blocking_reasons ?? []).length > 0 && (
                  <ul className="mt-4 space-y-1 text-xs text-danger">
                    {(result.blocking_reasons ?? []).map((r, i) => (
                      <li key={i} className="flex gap-2">
                        <ShieldBan className="mt-0.5 h-3 w-3 shrink-0" />
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              {(result.findings ?? []).map((f, i) => (
                <Panel key={i} className="p-5">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <h3 className="text-sm font-semibold text-ink-100">{f.title}</h3>
                    <span
                      className={classNames(
                        "rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                        f.status === "introduced"
                          ? "bg-danger/15 text-danger"
                          : f.status === "resolved"
                            ? "bg-ok/15 text-ok"
                            : "bg-ink-800 text-ink-400",
                      )}
                    >
                      {f.status.replace("_", " ")}
                    </span>
                    {f.cwe && <span className="font-mono text-[11px] text-ink-400">{f.cwe}</span>}
                  </div>
                  {f.file_path && (
                    <p className="mt-1 font-mono text-[11px] text-ink-500">
                      {f.file_path}
                      {f.line_start ? `:${f.line_start}` : ""}
                    </p>
                  )}
                  {(f.evidence ?? []).map((e, ei) => (
                    <div key={ei} className="mt-3 rounded-lg skeu-screen p-3">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] uppercase tracking-wider text-ink-500">{e.type}</span>
                        {e.classification && <ClassificationTag classification={e.classification} />}
                      </div>
                      {e.snippet && (
                        <pre className="mt-2 overflow-x-auto font-mono text-[11px] text-ink-300">{e.snippet}</pre>
                      )}
                      {e.explanation && <p className="mt-2 text-xs text-ink-400">{e.explanation}</p>}
                    </div>
                  ))}
                  {f.remediation && <p className="mt-3 text-xs text-cyber-200">{f.remediation}</p>}
                  {f.suggested_patch && (
                    <div className="mt-3">
                      <p className="stat-label mb-1">Suggested patch</p>
                      <CodeBlock code={f.suggested_patch} language="diff" />
                    </div>
                  )}
                </Panel>
              ))}

              {result.review_comment && (
                <Panel className="p-5">
                  <p className="stat-label mb-2">Review comment</p>
                  <p className="whitespace-pre-wrap text-xs leading-relaxed text-ink-300">{result.review_comment}</p>
                </Panel>
              )}
            </>
          )}

          {scans.length > 0 && (
            <Panel className="p-5">
              <p className="stat-label mb-3">Recent pull-request scans</p>
              <ul className="space-y-2">
                {scans.map((s) => {
                  const st = GATE_STYLE[s.gate_status] ?? GATE_STYLE.passed;
                  return (
                    <li key={s.id} className="flex items-center justify-between gap-2 text-xs">
                      <span className="min-w-0 truncate text-ink-300">
                        {s.pr_number ? `#${s.pr_number} ` : ""}
                        {s.title}
                      </span>
                      <span
                        className={classNames(
                          "shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                          st.cls,
                        )}
                      >
                        {s.gate_status}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </Panel>
          )}

          <Panel className="p-5">
            <p className="stat-label mb-2">CI wiring</p>
            <p className="mb-3 text-xs text-ink-400">
              Call the AegisCode gate from your pipeline and fail the job when the gate is blocked.
            </p>
            <CodeBlock
              language="yaml"
              code={`# .github/workflows/aegiscode.yml
name: AegisCode
on: [pull_request]
jobs:
  aegiscode:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: AegisCode PR gate
        run: |
          git diff origin/\${{ github.base_ref }}...HEAD > pr.diff
          curl -sS -X POST "$AEGIS_URL/api/public/pr-gate" \\
            -H "content-type: application/json" \\
            -H "x-aegis-signature: $AEGIS_SIGNATURE" \\
            --data @<(jq -Rs '{title: env.PR_TITLE, diff: .}' pr.diff) \\
            | tee gate.json
          test "$(jq -r .gate_status gate.json)" != "blocked"`}
            />
          </Panel>
        </div>
      </div>
    </div>
  );
}

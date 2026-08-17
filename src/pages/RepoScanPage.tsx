import { useEffect, useMemo, useState } from "react";
import {
  GitBranch,
  Loader2,
  AlertCircle,
  Play,
  Trash2,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  FileCode2,
  CircleCheck,
  CircleAlert,
} from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import { scanRepositoryFn } from "@/lib/scanner.functions";
import { diffScans, gateDecision, findingsDigest, type SastFinding, type SastSeverity } from "@/lib/engines/sast";
import {
  Panel,
  PageHeader,
  Button,
  SeverityBadge,
  StatCard,
  EmptyState,
  Toggle,
  LedDot,
} from "@/components/ui-kit";
import { classNames, timeAgo } from "@/lib/utils";

interface RepoRow {
  id: string;
  provider: string;
  owner: string;
  repo: string;
  branch: string;
  last_commit_sha: string | null;
  last_scan_at: string | null;
  auto_scan: boolean;
  block_on: SastSeverity;
  baseline: SastFinding[];
  seen_fingerprints: string[];
}

interface ScanRow {
  id: string;
  repo_id: string | null;
  repo_label: string;
  commit_sha: string | null;
  ref: string | null;
  files_scanned: number;
  lines_scanned: number;
  findings: SastFinding[];
  summary: { total?: number; critical?: number; high?: number; rules_triggered?: number };
  new_findings: SastFinding[];
  fixed_findings: SastFinding[];
  regressed_findings: SastFinding[];
  gate_status: string;
  created_at: string;
}

export function RepoScanPage() {
  const [repos, setRepos] = useState<RepoRow[]>([]);
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [repoInput, setRepoInput] = useState("");
  const [branch, setBranch] = useState("");
  const [token, setToken] = useState("");
  const [monitor, setMonitor] = useState(true);
  const [blockOn, setBlockOn] = useState<SastSeverity>("critical");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState<ScanRow | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [ruleFilter, setRuleFilter] = useState("all");

  const load = async () => {
    const [{ data: r }, { data: s }] = await Promise.all([
      supabase.from("monitored_repos").select("*").order("created_at", { ascending: false }),
      supabase.from("repo_scans").select("*").order("created_at", { ascending: false }).limit(40),
    ]);
    setRepos((r as RepoRow[]) ?? []);
    const list = (s as ScanRow[]) ?? [];
    setScans(list);
    setActive((prev) => prev ?? list[0] ?? null);
  };

  useEffect(() => {
    void load();
  }, []);

  const runScan = async (target: { repo: string; branch?: string; token?: string; row?: RepoRow }) => {
    setBusy(target.row?.id ?? "new");
    setError(null);
    setExplanation(null);
    try {
      const result = await scanRepositoryFn({
        data: {
          repo: target.repo,
          ...(target.branch ? { ref: target.branch } : {}),
          ...(target.token ? { token: target.token } : {}),
        },
      });

      const baseline = target.row?.baseline ?? [];
      const seen = target.row?.seen_fingerprints ?? [];
      const diff = diffScans(baseline, result.findings, seen);
      const effectiveBlock = target.row?.block_on ?? blockOn;
      const gate = gateDecision(result.findings, effectiveBlock);

      let repoId = target.row?.id ?? null;
      const [owner, repoName] = result.label.split("/");
      if (!repoId && (target.row || monitor)) {
        const { data: inserted } = await supabase
          .from("monitored_repos")
          .insert({
            provider: result.provider,
            owner: owner ?? result.label,
            repo: repoName ?? result.label,
            branch: result.ref,
            block_on: blockOn,
            auto_scan: true,
          } as never)
          .select("id")
          .single();
        repoId = (inserted as { id: string } | null)?.id ?? null;
      }

      if (repoId) {
        await supabase
          .from("monitored_repos")
          .update({
            last_commit_sha: result.commitSha,
            last_scan_at: new Date().toISOString(),
            baseline: result.findings,
            seen_fingerprints: [...new Set([...seen, ...result.findings.map((f) => f.fingerprint)])].slice(0, 4000),
            updated_at: new Date().toISOString(),
          } as never)
          .eq("id", repoId);
      }

      const { data: scanRow } = await supabase
        .from("repo_scans")
        .insert({
          repo_id: repoId,
          repo_label: result.label,
          commit_sha: result.commitSha,
          ref: result.ref,
          engine: "sast",
          files_scanned: result.filesScanned,
          lines_scanned: result.linesScanned,
          findings: result.findings,
          summary: { ...result.summary, languages: result.languages, truncated: result.truncated },
          new_findings: diff.added,
          fixed_findings: diff.fixed,
          regressed_findings: diff.regressed,
          gate_status: gate.status,
        } as never)
        .select("*")
        .single();

      if (scanRow) setActive(scanRow as ScanRow);
      setRepoInput("");
      setBranch("");
      setToken("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const removeRepo = async (id: string) => {
    await supabase.from("monitored_repos").delete().eq("id", id);
    await load();
  };

  const explain = async () => {
    if (!active) return;
    setExplaining(true);
    setExplanation(null);
    try {
      const res = await ai.chat([
        {
          role: "user",
          content: `A deterministic SAST engine scanned ${active.repo_label} (commit ${active.commit_sha?.slice(0, 8)}) and produced these rule-based findings. Explain, for an engineer, what they mean, which ones to fix first and why. Reference the exact file:line for each. Do not invent findings that are not listed.\n\n${findingsDigest(
            active.findings,
          )}`,
        },
      ]);
      setExplanation(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExplaining(false);
    }
  };

  const rules = useMemo(
    () => [...new Set((active?.findings ?? []).map((f) => f.ruleId))].sort(),
    [active],
  );
  const visible = (active?.findings ?? []).filter((f) => ruleFilter === "all" || f.ruleId === ruleFilter);

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Repository Scanner (SAST)"
        subtitle="Deterministic rule + pattern analysis over an entire repository — every finding has a file, line and rule id. AI only explains what the engine proves."
        icon={<GitBranch className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-2">
          <Panel className="p-5">
            <label className="label">Repository</label>
            <input
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
              placeholder="owner/repo or https://github.com/owner/repo"
              className="input w-full font-mono text-[13px]"
            />
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <div>
                <label className="label">Branch (optional)</label>
                <input
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="default branch"
                  className="input w-full font-mono text-[13px]"
                />
              </div>
              <div>
                <label className="label">Block builds on</label>
                <select
                  value={blockOn}
                  onChange={(e) => setBlockOn(e.target.value as SastSeverity)}
                  className="input w-full"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High and above</option>
                  <option value="medium">Medium and above</option>
                </select>
              </div>
            </div>
            <div className="mt-3">
              <label className="label">Access token (private repos, optional)</label>
              <input
                value={token}
                onChange={(e) => setToken(e.target.value)}
                type="password"
                autoComplete="off"
                placeholder="ghp_… / glpat-…"
                className="input w-full font-mono text-[13px]"
              />
              <p className="mt-1 text-[11px] text-ink-500">
                Used once for this scan to read the repository. It is never stored.
              </p>
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <Toggle
                checked={monitor}
                onChange={setMonitor}
                label="Continuously monitor this repository"
              />
            </div>
            <Button
              onClick={() =>
                runScan({
                  repo: repoInput,
                  ...(branch ? { branch } : {}),
                  ...(token ? { token } : {}),
                })
              }
              disabled={busy !== null || repoInput.trim().length < 3}
              className="mt-4 w-full"
            >
              {busy === "new" ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" /> Cloning & scanning…
                </span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  <Play className="h-4 w-4" /> Scan repository
                </span>
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
            <p className="stat-label mb-3">Monitored repositories</p>
            {repos.length === 0 ? (
              <p className="text-xs text-ink-500">No repositories connected yet.</p>
            ) : (
              <ul className="space-y-2">
                {repos.map((r) => (
                  <li key={r.id} className="rounded-lg p-3 skeu-screen">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-xs text-ink-200">
                          {r.owner}/{r.repo}
                        </p>
                        <p className="mt-0.5 text-[11px] text-ink-500">
                          {r.provider} · {r.branch} ·{" "}
                          {r.last_scan_at ? `scanned ${timeAgo(r.last_scan_at)}` : "never scanned"}
                        </p>
                        <p className="mt-0.5 flex items-center gap-1.5 text-[11px] text-ink-500">
                          <LedDot color={r.auto_scan ? "#7cf03d" : "#5a6472"} />
                          {r.auto_scan ? "watching new commits" : "monitoring paused"} · gate:{" "}
                          {r.block_on}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <button
                          onClick={() => runScan({ repo: `${r.owner}/${r.repo}`, branch: r.branch, row: r })}
                          disabled={busy !== null}
                          title="Re-scan and verify fixes"
                          className="rounded-md p-1.5 text-ink-400 transition-colors hover:text-cyber-300 disabled:opacity-40"
                        >
                          {busy === r.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <RefreshCw className="h-4 w-4" />
                          )}
                        </button>
                        <button
                          onClick={() => removeRepo(r.id)}
                          title="Remove"
                          className="rounded-md p-1.5 text-ink-400 transition-colors hover:text-danger"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel className="p-5">
            <p className="stat-label mb-3">Scan history</p>
            {scans.length === 0 ? (
              <p className="text-xs text-ink-500">No scans yet.</p>
            ) : (
              <ul className="space-y-1.5">
                {scans.map((s) => (
                  <li key={s.id}>
                    <button
                      onClick={() => {
                        setActive(s);
                        setExplanation(null);
                        setRuleFilter("all");
                      }}
                      className={classNames(
                        "w-full rounded-lg px-3 py-2 text-left transition-colors",
                        active?.id === s.id ? "bg-cyber-500/10" : "hover:bg-ink-800/30",
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate font-mono text-[11px] text-ink-300">{s.repo_label}</span>
                        <span
                          className={classNames(
                            "chip border text-[10px]",
                            s.gate_status === "failed"
                              ? "border-danger/30 bg-danger/15 text-danger"
                              : "border-volt-500/25 bg-volt-500/10 text-volt-300",
                          )}
                        >
                          {s.gate_status}
                        </span>
                      </div>
                      <p className="mt-0.5 text-[10px] text-ink-500">
                        {s.commit_sha?.slice(0, 8) ?? "—"} · {s.summary?.total ?? 0} findings · {timeAgo(s.created_at)}
                      </p>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        <div className="space-y-4 lg:col-span-3">
          {!active ? (
            <Panel className="p-10">
              <EmptyState
                icon={<GitBranch className="h-8 w-8" />}
                title="No repository scanned yet"
                description="Point AegisCode at a GitHub or GitLab repository. The engine downloads the source tree and applies deterministic security rules across every file — no AI guessing."
              />
            </Panel>
          ) : (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <StatCard label="Findings" value={active.summary?.total ?? active.findings.length} accent="danger" />
                <StatCard label="Files scanned" value={active.files_scanned} accent="cyber" />
                <StatCard label="Lines analysed" value={active.lines_scanned.toLocaleString()} accent="default" />
                <StatCard label="Rules triggered" value={active.summary?.rules_triggered ?? 0} accent="volt" />
              </div>

              <Panel className="p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-mono text-sm text-ink-100">{active.repo_label}</p>
                    <p className="mt-0.5 text-xs text-ink-500">
                      {active.ref} @ {active.commit_sha?.slice(0, 10) ?? "—"} · scanned {timeAgo(active.created_at)}
                    </p>
                  </div>
                  <span
                    className={classNames(
                      "flex items-center gap-1.5 rounded px-2 py-1 text-[10px] font-bold uppercase tracking-wider",
                      active.gate_status === "failed" ? "bg-danger/15 text-danger" : "bg-volt-500/15 text-volt-300",
                    )}
                  >
                    <ShieldCheck className="h-3.5 w-3.5" />
                    CI gate {active.gate_status}
                  </span>
                </div>

                <div className="mt-4 grid gap-3 sm:grid-cols-3">
                  <DiffCard
                    icon={<CircleAlert className="h-4 w-4 text-danger" />}
                    label="New since last scan"
                    items={active.new_findings}
                  />
                  <DiffCard
                    icon={<CircleCheck className="h-4 w-4 text-volt-300" />}
                    label="Verified fixed"
                    items={active.fixed_findings}
                  />
                  <DiffCard
                    icon={<RefreshCw className="h-4 w-4 text-warning" />}
                    label="Regressions"
                    items={active.regressed_findings}
                  />
                </div>
              </Panel>

              <Panel className="p-5">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <p className="stat-label !mb-0">Engine findings</p>
                  <div className="flex items-center gap-2">
                    <select
                      value={ruleFilter}
                      onChange={(e) => setRuleFilter(e.target.value)}
                      className="input w-auto text-xs"
                    >
                      <option value="all">All rules ({active.findings.length})</option>
                      {rules.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                    <Button size="sm" variant="ghost" onClick={explain} disabled={explaining || active.findings.length === 0}>
                      {explaining ? (
                        <span className="flex items-center gap-1.5">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Explaining
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5">
                          <Sparkles className="h-3.5 w-3.5" /> Explain with AI
                        </span>
                      )}
                    </Button>
                  </div>
                </div>

                {visible.length === 0 ? (
                  <p className="py-8 text-center text-sm text-ink-400">
                    No rule matched in this repository snapshot.
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {visible.slice(0, 200).map((f) => (
                      <li key={f.id} className="rounded-lg p-3 skeu-screen">
                        <div className="flex flex-wrap items-center gap-2">
                          <SeverityBadge severity={f.severity} />
                          <span className="text-xs font-semibold text-ink-200">{f.title}</span>
                          <span className="font-mono text-[11px] text-ink-400">{f.cwe}</span>
                          <span className="chip border border-ink-700/60 bg-ink-800/60 font-mono text-[10px] text-ink-400">
                            {f.ruleId}
                          </span>
                          <span className="font-mono text-[11px] text-ink-500">
                            {Math.round(f.confidence * 100)}% confidence
                          </span>
                        </div>
                        <p className="mt-1.5 flex items-center gap-1.5 font-mono text-[11px] text-cyber-300">
                          <FileCode2 className="h-3.5 w-3.5" />
                          {f.file}:{f.line}:{f.column}
                        </p>
                        <pre className="mt-2 overflow-x-auto rounded bg-ink-950/50 p-2 font-mono text-[11px] leading-relaxed text-ink-300">
                          {f.snippet}
                        </pre>
                        <p className="mt-2 text-xs text-ink-400">{f.message}</p>
                        <p className="mt-1 text-xs text-cyber-200">{f.remediation}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              {explanation && (
                <Panel className="p-5">
                  <p className="stat-label mb-2">AI explanation of engine findings</p>
                  <p className="whitespace-pre-wrap text-xs leading-relaxed text-ink-300">{explanation}</p>
                </Panel>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function DiffCard({
  icon,
  label,
  items,
}: {
  icon: React.ReactNode;
  label: string;
  items: SastFinding[];
}) {
  return (
    <div className="rounded-lg p-3 skeu-screen">
      <div className="flex items-center gap-2">
        {icon}
        <p className="text-[10px] font-semibold uppercase tracking-wider text-ink-500">{label}</p>
      </div>
      <p className="mt-1 font-mono text-lg text-ink-100">{items?.length ?? 0}</p>
      <ul className="mt-1 space-y-0.5">
        {(items ?? []).slice(0, 3).map((f) => (
          <li key={f.id} className="truncate text-[11px] text-ink-400">
            {f.file}:{f.line} — {f.title}
          </li>
        ))}
      </ul>
    </div>
  );
}

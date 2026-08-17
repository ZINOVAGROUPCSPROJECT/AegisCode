import { useEffect, useState } from "react";
import { ShieldAlert, Search, Filter, ChevronRight, Loader2 } from "lucide-react";
import { supabase } from "@/lib/db";
import type { Finding, Scan } from "@/lib/types";
import {
  Panel,
  SeverityBadge,
  ExploitabilityBadge,
  CvssScore,
  KevBadge,
  EmptyState,
  PageHeader,
  Button,
  Modal,
  ClassificationTag,
  CodeBlock,
} from "@/components/ui-kit";
import { classNames, timeAgo, severityRank } from "@/lib/utils";
import type { PageId } from "@/components/AppShell";

export function CodeSecurityPage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [selected, setSelected] = useState<Finding | null>(null);

  useEffect(() => {
    (async () => {
      const [{ data: fData }, { data: sData }] = await Promise.all([
        supabase.from("findings").select("*").order("created_at", { ascending: false }),
        supabase.from("scans").select("*").order("created_at", { ascending: false }),
      ]);
      setFindings((fData as Finding[]) ?? []);
      setScans(sData ?? []);
      setLoading(false);
    })();
  }, []);

  const filtered = findings
    .filter((f) => sevFilter === "all" || f.severity === sevFilter)
    .filter(
      (f) =>
        !search ||
        f.title.toLowerCase().includes(search.toLowerCase()) ||
        (f.cwe ?? "").toLowerCase().includes(search.toLowerCase()) ||
        (f.description ?? "").toLowerCase().includes(search.toLowerCase())
    )
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const scanName = (id: string) => scans.find((s) => s.id === id)?.name ?? "Unknown scan";

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
        title="Code Security"
        subtitle="All vulnerabilities discovered across your scans, prioritized by severity and exploitability."
        icon={<ShieldAlert className="h-6 w-6" />}
        actions={
          <Button size="sm" onClick={() => onNavigate("analyze")}>
            New Analysis
          </Button>
        }
      />

      {findings.length === 0 ? (
        <Panel className="p-8">
          <EmptyState
            icon={<ShieldAlert className="h-12 w-12" />}
            title="No findings yet"
            description="Run a code analysis to discover vulnerabilities. They will appear here with full evidence chains and exploitability verdicts."
            action={<Button onClick={() => onNavigate("analyze")}>Go to Analyze</Button>}
          />
        </Panel>
      ) : (
        <>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-ink-500" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search findings, CWE, description..."
                className="input pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-ink-500" />
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} className="input w-auto">
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>

          <Panel className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-ink-700/60 text-left text-xs text-ink-500">
                    <th className="px-4 py-3 font-medium">Finding</th>
                    <th className="px-4 py-3 font-medium">Severity</th>
                    <th className="px-4 py-3 font-medium">Exploitability</th>
                    <th className="px-4 py-3 font-medium">CWE</th>
                    <th className="px-4 py-3 font-medium">CVSS</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Scan</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => setSelected(f)}
                      className="cursor-pointer border-b border-ink-800/50 transition-colors hover:bg-ink-800/30"
                    >
                      <td className="px-4 py-3 max-w-xs">
                        <p className="truncate font-medium text-ink-100">{f.title}</p>
                        <p className="mt-0.5 truncate text-xs text-ink-500">{f.location || "—"}</p>
                      </td>
                      <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                      <td className="px-4 py-3"><ExploitabilityBadge exploitability={f.exploitability} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-ink-300">{f.cwe || "—"}</td>
                      <td className="px-4 py-3"><CvssScore score={f.cvss_score} /></td>
                      <td className="px-4 py-3">
                        <span
                          className={classNames(
                            "chip border",
                            f.status === "verified"
                              ? "text-volt-300 bg-volt-500/10 border-volt-500/25"
                              : f.status === "remediated"
                              ? "text-cyber-300 bg-cyber-500/10 border-cyber-500/25"
                              : f.status === "ignored"
                              ? "text-ink-500 bg-ink-800/40 border-ink-700/40"
                              : "text-warning bg-warning/10 border-warning/20"
                          )}
                        >
                          {f.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-ink-500">{timeAgo(f.created_at)}</td>
                      <td className="px-4 py-3"><ChevronRight className="h-4 w-4 text-ink-600" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filtered.length === 0 && (
              <div className="py-12 text-center text-sm text-ink-400">No findings match your filters.</div>
            )}
          </Panel>
        </>
      )}

      <FindingDetailModal finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

function FindingDetailModal({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  if (!finding) return null;
  return (
    <Modal open={!!finding} onClose={onClose} title={finding.title} maxWidth="max-w-3xl">
      <div className="space-y-4 max-h-[60vh] overflow-y-auto">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <ExploitabilityBadge exploitability={finding.exploitability} />
          {finding.cwe && (
            <span className="chip border border-ink-700/60 bg-ink-800/60 font-mono text-ink-300">{finding.cwe}</span>
          )}
          <KevBadge inKev={finding.in_kev} />
          <ClassificationTag classification={finding.reachability} />
          <span className="text-xs text-ink-500 font-mono">{finding.exploit_confidence}% confidence</span>
        </div>

        {finding.description && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1">Description</p>
            <p className="text-sm text-ink-300">{finding.description}</p>
          </div>
        )}

        {finding.location && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1">Location</p>
            <p className="font-mono text-xs text-ink-300">{finding.location}</p>
          </div>
        )}

        {finding.verdict && typeof finding.verdict === "object" && "reasoning" in (finding.verdict as Record<string, unknown>) && (
          <div className="rounded-lg border border-ink-700/40 bg-ink-950/40 p-3">
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1">Application-Aware Verdict</p>
            <p className="text-sm text-ink-300">{(finding.verdict as Record<string, unknown>)["reasoning"] as string}</p>
          </div>
        )}

        {Array.isArray(finding.evidence) && finding.evidence.length > 0 && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Evidence</p>
            <div className="space-y-2">
              {(finding.evidence as Array<Record<string, unknown>>).map((ev, i) => (
                <div key={i} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                  {ev["snippet"] ? (
                    <pre className="mb-1.5 overflow-x-auto rounded bg-ink-950/60 p-2 font-mono text-xs text-ink-200">
                      {String(ev["snippet"])}
                    </pre>
                  ) : null}
                  {ev["explanation"] ? <p className="text-xs text-ink-400">{String(ev["explanation"])}</p> : null}
                </div>
              ))}
            </div>
          </div>
        )}

        {finding.secure_fix && (
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Secure Fix</p>
            <CodeBlock code={finding.secure_fix} />
          </div>
        )}
      </div>
    </Modal>
  );
}

import { useEffect, useState } from "react";
import { Globe, Loader2, AlertCircle, Search, TrendingUp, Database, ShieldAlert } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { ThreatIntelRecord, Finding, AIThreatIntelResult } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  EmptyState,
  StatCard,
  ClassificationTag,
  KevBadge,
  CvssScore,
  EpssScore,
} from "@/components/ui-kit";
import { classNames, timeAgo } from "@/lib/utils";

const SOURCES = ["nvd", "osv", "cisa-kev", "epss", "vendor", "internal", "custom"];

export function ThreatIntelPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [savedIntel, setSavedIntel] = useState<ThreatIntelRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIThreatIntelResult | null>(null);
  const [cveInput, setCveInput] = useState("");
  const [context, setContext] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");

  useEffect(() => {
    (async () => {
      const [{ data: f }, { data: t }] = await Promise.all([
        supabase.from("findings").select("*").order("created_at", { ascending: false }).limit(50),
        supabase.from("threat_intel").select("*").order("created_at", { ascending: false }).limit(30),
      ]);
      setFindings((f as Finding[]) ?? []);
      setSavedIntel((t as ThreatIntelRecord[]) ?? []);
      setLoading(false);
    })();
  }, []);

  const runFusion = async () => {
    setAnalyzing(true);
    setError(null);
    setResult(null);
    try {
      const cves = cveInput
        .split(/[,\s\n]+/)
        .map((c) => c.trim().toUpperCase())
        .filter((c) => c.startsWith("CVE-"));
      const ctx = context || findings.map((f) => f.cwe).filter(Boolean).join(", ") || "No specific context.";
      const res = await ai.fuseThreatIntel(cves, ctx);

      if (res.records) {
        const rows = res.records.map((r) => ({
          cve: r.cve,
          source: r.source,
          description: r.description,
          cvss_score: r.cvss_score,
          epss_score: r.epss_score,
          epss_percentile: r.epss_percentile,
          in_kev: r.in_kev,
          kev_date: r.kev_date,
          intel_references: r.references,
          raw: { classification: r.classification },
        }));
        if (rows.length > 0) {
          await supabase.from("threat_intel").insert(rows as never);
        }
      }
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setAnalyzing(false);
    }
  };

  const filteredIntel = savedIntel.filter((t) => sourceFilter === "all" || t.source === sourceFilter);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-cyber-400" />
      </div>
    );
  }

  const kevCount = savedIntel.filter((t) => t.in_kev).length;
  const highScoreCount = savedIntel.filter((t) => (t.cvss_score ?? 0) >= 7).length;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Threat Intelligence Fusion"
        subtitle="Correlate CVE/NVD/OSV/CISA KEV/EPSS/vendor intelligence to enrich your findings with real-world exploitability data."
        icon={<Globe className="h-6 w-6" />}
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Intel Records" value={savedIntel.length} icon={<Database className="h-5 w-5" />} accent="cyber" />
        <StatCard label="CISA KEV" value={kevCount} icon={<ShieldAlert className="h-5 w-5" />} accent="danger" />
        <StatCard label="High CVSS" value={highScoreCount} icon={<TrendingUp className="h-5 w-5" />} accent="warning" />
        <StatCard label="Sources" value={SOURCES.length} icon={<Globe className="h-5 w-5" />} accent="default" />
      </div>

      <Panel className="p-5">
        <h3 className="mb-3 text-sm font-semibold text-ink-100">Run Threat Intelligence Fusion</h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label">CVE IDs (comma or newline separated)</label>
            <textarea
              value={cveInput}
              onChange={(e) => setCveInput(e.target.value)}
              placeholder="CVE-2021-44228, CVE-2022-22965..."
              rows={3}
              className="textarea"
            />
          </div>
          <div>
            <label className="label">Context (optional)</label>
            <textarea
              value={context}
              onChange={(e) => setContext(e.target.value)}
              placeholder="Application context, affected components, or CWEs to correlate..."
              rows={3}
              className="textarea"
            />
          </div>
        </div>
        <Button onClick={runFusion} disabled={analyzing} className="mt-3">
          {analyzing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
          {analyzing ? "Fusing Intel..." : "Fuse Threat Intelligence"}
        </Button>
        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </Panel>

      {result && (
        <Panel className="p-5 animate-fade-in">
          <h3 className="mb-3 text-sm font-semibold text-ink-100">Fusion Results</h3>
          {result.fusion_summary && <p className="mb-4 text-sm text-ink-300">{result.fusion_summary}</p>}
          <div className="space-y-2">
            {result.records.map((r, i) => (
              <div key={i} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className="font-mono text-sm font-semibold text-ink-100">{r.cve}</span>
                  <span className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400 uppercase">{r.source}</span>
                  <KevBadge inKev={r.in_kev} />
                  {r.classification && <ClassificationTag classification={r.classification} />}
                </div>
                <p className="text-xs text-ink-400 mb-2">{r.description}</p>
                <div className="flex flex-wrap items-center gap-4">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] uppercase tracking-wider text-ink-500">CVSS</span>
                    <CvssScore score={r.cvss_score} />
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] uppercase tracking-wider text-ink-500">EPSS</span>
                    <EpssScore score={r.epss_score} percentile={r.epss_percentile} />
                  </div>
                </div>
                {r.references && r.references.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {r.references.slice(0, 4).map((ref, j) => (
                      <a
                        key={j}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="chip border border-cyber-500/25 bg-cyber-500/10 text-[10px] text-cyber-300 hover:bg-cyber-500/20"
                      >
                        {ref.source}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}

      <div>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-ink-100">Saved Intelligence</h3>
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-ink-500" />
            <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} className="input w-auto">
              <option value="all">All sources</option>
              {SOURCES.map((s) => (
                <option key={s} value={s}>{s.toUpperCase()}</option>
              ))}
            </select>
          </div>
        </div>
        {filteredIntel.length === 0 ? (
          <Panel className="p-8">
            <EmptyState
              icon={<Globe className="h-12 w-12" />}
              title="No Intelligence Records"
              description="Run a fusion analysis or correlate CVEs to populate your threat intelligence database."
            />
          </Panel>
        ) : (
          <Panel className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-ink-700/60 text-left text-xs text-ink-500">
                    <th className="px-4 py-3 font-medium">CVE</th>
                    <th className="px-4 py-3 font-medium">Source</th>
                    <th className="px-4 py-3 font-medium">CVSS</th>
                    <th className="px-4 py-3 font-medium">EPSS</th>
                    <th className="px-4 py-3 font-medium">KEV</th>
                    <th className="px-4 py-3 font-medium">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIntel.map((t) => (
                    <tr key={t.id} className="border-b border-ink-800/50">
                      <td className="px-4 py-3 font-mono text-ink-200">{t.cve || "—"}</td>
                      <td className="px-4 py-3">
                        <span className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400 uppercase">{t.source}</span>
                      </td>
                      <td className="px-4 py-3"><CvssScore score={t.cvss_score} /></td>
                      <td className="px-4 py-3"><EpssScore score={t.epss_score} percentile={t.epss_percentile} /></td>
                      <td className="px-4 py-3">{t.in_kev ? <KevBadge inKev /> : <span className="text-ink-600 text-xs">—</span>}</td>
                      <td className="px-4 py-3 text-xs text-ink-500">{timeAgo(t.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}

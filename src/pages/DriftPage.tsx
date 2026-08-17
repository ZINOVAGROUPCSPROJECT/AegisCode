import { useEffect, useState } from "react";
import { GitCompareArrows, Loader2, AlertCircle, FileUp, ArrowRight } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { DriftRecord, AIDriftResult } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  EmptyState,
  SeverityBadge,
  ClassificationTag,
  StatCard,
} from "@/components/ui-kit";
import { classNames, timeAgo, sha256 } from "@/lib/utils";

export function DriftPage() {
  const [before, setBefore] = useState("");
  const [after, setAfter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIDriftResult | null>(null);
  const [records, setRecords] = useState<DriftRecord[]>([]);

  useEffect(() => {
    (async () => {
      const { data } = await supabase.from("drift_records").select("*").order("created_at", { ascending: false }).limit(30);
      setRecords((data as DriftRecord[]) ?? []);
    })();
  }, []);

  const handleAnalyze = async () => {
    if (!before.trim() || !after.trim()) {
      setError("Please provide both before and after states.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const hash = await sha256(before + after);
      const { data: scanRow } = await supabase
        .from("scans")
        .insert({
          name: `Drift Detection — ${new Date().toLocaleString()}`,
          scan_type: "drift",
          status: "running",
          input_hash: hash,
        })
        .select()
        .single();

      const res = await ai.detectDrift(before, after);
      setResult(res);

      if (scanRow && res.drift_records) {
        await supabase.from("scans").update({ status: "completed" }).eq("id", scanRow.id);
        const rows = res.drift_records.map((r) => ({
          scan_id: scanRow.id,
          drift_type: r.drift_type,
          description: r.description,
          severity: r.severity,
          before_state: { input: before.slice(0, 500) },
          after_state: { input: after.slice(0, 500) },
          security_impact: r.security_impact,
        }));
        if (rows.length > 0) {
          await supabase.from("drift_records").insert(rows as never);
          const { data: newRecords } = await supabase
            .from("drift_records")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(30);
          setRecords((newRecords as DriftRecord[]) ?? []);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>, setter: (v: string) => void) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setter(reader.result as string);
    reader.readAsText(file);
  };

  const criticalCount = records.filter((r) => r.severity === "critical" || r.severity === "high").length;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Security Drift Detection"
        subtitle="Detect security-relevant changes in dependencies, code, configuration, artifacts, and behavior between two states."
        icon={<GitCompareArrows className="h-6 w-6" />}
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Drift" value={records.length} icon={<GitCompareArrows className="h-5 w-5" />} accent="cyber" />
        <StatCard label="Critical/High" value={criticalCount} icon={<AlertCircle className="h-5 w-5" />} accent="danger" />
        <StatCard label="Dependency" value={records.filter((r) => r.drift_type === "dependency").length} accent="warning" />
        <StatCard label="Code" value={records.filter((r) => r.drift_type === "code").length} accent="default" />
      </div>

      <Panel className="p-5">
        <h3 className="mb-3 text-sm font-semibold text-ink-100">Compare States</h3>
        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="label !mb-0">Before State</label>
              <label className="btn-ghost !px-2 !py-1 !text-xs cursor-pointer">
                <FileUp className="h-3 w-3" />
                Upload
                <input type="file" className="hidden" onChange={(e) => handleFile(e, setBefore)} accept=".json,.txt,.yaml,.yml,.toml,.lock" />
              </label>
            </div>
            <textarea
              value={before}
              onChange={(e) => setBefore(e.target.value)}
              placeholder="Paste the before state (package.json, config, code, etc.)"
              rows={10}
              className="textarea"
            />
          </div>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="label !mb-0">After State</label>
              <label className="btn-ghost !px-2 !py-1 !text-xs cursor-pointer">
                <FileUp className="h-3 w-3" />
                Upload
                <input type="file" className="hidden" onChange={(e) => handleFile(e, setAfter)} accept=".json,.txt,.yaml,.yml,.toml,.lock" />
              </label>
            </div>
            <textarea
              value={after}
              onChange={(e) => setAfter(e.target.value)}
              placeholder="Paste the after state (package.json, config, code, etc.)"
              rows={10}
              className="textarea"
            />
          </div>
        </div>
        <Button onClick={handleAnalyze} disabled={loading || !before.trim() || !after.trim()} className="mt-3">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitCompareArrows className="h-4 w-4" />}
          {loading ? "Detecting Drift..." : "Detect Security Drift"}
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
          <h3 className="mb-3 text-sm font-semibold text-ink-100">Drift Analysis Results</h3>
          {result.summary && <p className="mb-4 text-sm text-ink-300">{result.summary}</p>}
          <div className="space-y-2">
            {result.drift_records.map((r, i) => (
              <div key={i} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400 uppercase">{r.drift_type}</span>
                    <SeverityBadge severity={r.severity} />
                    {r.classification && <ClassificationTag classification={r.classification} />}
                  </div>
                </div>
                <p className="text-sm text-ink-200">{r.description}</p>
                {r.security_impact && (
                  <div className="mt-2 rounded border border-warning/20 bg-warning/5 p-2 text-xs text-warning">
                    Impact: {r.security_impact}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}

      <div>
        <h3 className="mb-3 text-sm font-semibold text-ink-100">Drift History</h3>
        {records.length === 0 ? (
          <Panel className="p-8">
            <EmptyState
              icon={<GitCompareArrows className="h-12 w-12" />}
              title="No Drift Detected"
              description="Compare two states to detect security-relevant changes. Results are saved here."
            />
          </Panel>
        ) : (
          <div className="space-y-2">
            {records.map((r) => (
              <Panel key={r.id} className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400 uppercase">{r.drift_type}</span>
                    <SeverityBadge severity={r.severity} />
                  </div>
                  <span className="text-xs text-ink-500">{timeAgo(r.created_at)}</span>
                </div>
                <p className="mt-2 text-sm text-ink-200">{r.description}</p>
                {r.security_impact && (
                  <p className="mt-1 text-xs text-warning">Impact: {r.security_impact}</p>
                )}
              </Panel>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

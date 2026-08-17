import { useState, useEffect } from "react";
import { Package, Loader2, AlertCircle, FileUp, Bug, Skull, Activity, Zap } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { Dependency, AISupplyChainResult } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  RiskBadge,
  EmptyState,
  StatCard,
  ClassificationTag,
} from "@/components/ui-kit";
import { classNames, sha256, countLines } from "@/lib/utils";

const SAMPLE_MANIFEST = `{
  "name": "my-app",
  "version": "1.2.0",
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.4",
    "axios": "0.19.0",
    "jsonwebtoken": "8.5.1",
    "bcrypt": "3.0.0",
    "request": "2.88.0"
  }
}`;

export function SupplyChainPage() {
  const [manifest, setManifest] = useState("");
  const [appContext, setAppContext] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AISupplyChainResult | null>(null);
  const [savedDeps, setSavedDeps] = useState<Dependency[]>([]);

  useEffect(() => {
    (async () => {
      const { data } = await supabase
        .from("dependencies")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(20);
      setSavedDeps((data as Dependency[]) ?? []);
    })();
  }, []);

  const handleAnalyze = async () => {
    if (!manifest.trim()) {
      setError("Please paste a dependency manifest (package.json, requirements.txt, go.mod, etc.)");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const hash = await sha256(manifest);
      const { data: scanRow } = await supabase
        .from("scans")
        .insert({
          name: `Supply Chain Scan — ${new Date().toLocaleString()}`,
          scan_type: "supply_chain",
          status: "running",
          input_hash: hash,
          loc: countLines(manifest),
        })
        .select()
        .single();

      const res = await ai.analyzeSupplyChain(manifest, appContext || "No additional context provided.");
      setResult(res);

      if (scanRow && res.dependencies) {
        await supabase.from("scans").update({ status: "completed", summary: res.summary as Record<string, unknown> }).eq("id", scanRow.id);
        const rows = res.dependencies.map((d) => ({
          scan_id: scanRow.id,
          name: d.name,
          version: d.version,
          ecosystem: d.ecosystem,
          direct: true,
          risk_level: d.risk_level,
          vulnerabilities: d.vulnerabilities,
          poisoning_indicators: d.poisoning_indicators,
          behavioral_fingerprint: d.behavioral_fingerprint,
          blast_radius: d.blast_radius,
          reachability: d.reachability,
        }));
        if (rows.length > 0) {
          await supabase.from("dependencies").insert(rows as never);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setManifest(reader.result as string);
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Supply-Chain Security"
        subtitle="SBOM generation, dependency risk, poisoning indicators, behavioral fingerprinting, and blast radius analysis."
        icon={<Package className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <div className="mb-3 flex items-center justify-between">
              <label className="label !mb-0">Dependency Manifest / SBOM</label>
              <div className="flex gap-2">
                <label className="btn-ghost !px-3 !py-1.5 !text-xs cursor-pointer">
                  <FileUp className="h-3.5 w-3.5" />
                  Upload
                  <input type="file" className="hidden" onChange={handleFile} accept=".json,.txt,.toml,.lock,.yaml,.yml" />
                </label>
                <button onClick={() => setManifest(SAMPLE_MANIFEST)} className="btn-ghost !px-3 !py-1.5 !text-xs">
                  Sample
                </button>
              </div>
            </div>
            <textarea
              value={manifest}
              onChange={(e) => setManifest(e.target.value)}
              placeholder="Paste package.json, requirements.txt, go.mod, pom.xml..."
              rows={14}
              className="textarea"
            />
            <div className="mt-3">
              <label className="label">Application Context (optional)</label>
              <input
                value={appContext}
                onChange={(e) => setAppContext(e.target.value)}
                placeholder="e.g. Node.js REST API with user authentication"
                className="input"
              />
            </div>
            <Button onClick={handleAnalyze} disabled={loading || !manifest.trim()} className="mt-3 w-full" size="lg">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Package className="h-4 w-4" />}
              {loading ? "Analyzing Supply Chain..." : "Analyze Supply Chain"}
            </Button>
            {error && (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </Panel>
        </div>

        <div className="lg:col-span-3 space-y-4">
          {loading && (
            <Panel className="p-8 scanline">
              <div className="flex flex-col items-center text-center">
                <Loader2 className="h-8 w-8 animate-spin text-cyber-400" />
                <p className="mt-3 text-sm text-ink-300">Analyzing supply chain...</p>
                <p className="mt-1 text-xs text-ink-500">Building SBOM, assessing dependency risk, detecting poisoning indicators</p>
              </div>
            </Panel>
          )}

          {!loading && !result && (
            <Panel className="p-8">
              <EmptyState
                icon={<Package className="h-12 w-12" />}
                title="No Analysis Yet"
                description="Paste a dependency manifest and run a supply-chain analysis. Results include SBOM, risk levels, poisoning indicators, and blast radius."
              />
            </Panel>
          )}

          {result && (
            <>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <StatCard label="Dependencies" value={result.summary.total} icon={<Package className="h-5 w-5" />} accent="cyber" />
                <StatCard label="Critical Risk" value={result.summary.critical} icon={<Skull className="h-5 w-5" />} accent="danger" />
                <StatCard label="High Risk" value={result.summary.high} icon={<Zap className="h-5 w-5" />} accent="warning" />
                <StatCard label="Poisoning Risk" value={result.summary.poisoning_risk + "%"} icon={<Activity className="h-5 w-5" />} accent="danger" />
              </div>

              {result.sbom && result.sbom.length > 0 && (
                <Panel className="p-5">
                  <h3 className="mb-3 text-sm font-semibold text-ink-100">Software Bill of Materials (SBOM)</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-ink-700/60 text-left text-xs text-ink-500">
                          <th className="pb-2 pr-4 font-medium">Name</th>
                          <th className="pb-2 pr-4 font-medium">Version</th>
                          <th className="pb-2 pr-4 font-medium">Ecosystem</th>
                          <th className="pb-2 pr-4 font-medium">License</th>
                          <th className="pb-2 font-medium">Type</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.sbom.map((dep, i) => (
                          <tr key={i} className="border-b border-ink-800/50">
                            <td className="py-2 pr-4 font-mono text-ink-200">{dep.name}</td>
                            <td className="py-2 pr-4 font-mono text-xs text-ink-400">{dep.version}</td>
                            <td className="py-2 pr-4 text-xs text-ink-400">{dep.ecosystem}</td>
                            <td className="py-2 pr-4 text-xs text-ink-400">{dep.license || "—"}</td>
                            <td className="py-2">
                              <span className={classNames("chip border", dep.direct ? "text-cyber-300 bg-cyber-500/10 border-cyber-500/25" : "text-ink-400 bg-ink-800/40 border-ink-700/40")}>
                                {dep.direct ? "Direct" : "Transitive"}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              )}

              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-ink-100">Dependency Risk Analysis</h3>
                {result.dependencies.map((dep, i) => (
                  <Panel key={i} className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div>
                        <p className="font-mono font-semibold text-ink-100">{dep.name}</p>
                        <p className="text-xs text-ink-500">{dep.version} · {dep.ecosystem}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <RiskBadge risk={dep.risk_level} />
                        <ClassificationTag classification={dep.reachability} />
                      </div>
                    </div>

                    {dep.vulnerabilities && dep.vulnerabilities.length > 0 && (
                      <div className="mb-3">
                        <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1.5 flex items-center gap-1">
                          <Bug className="h-3 w-3" /> Vulnerabilities
                        </p>
                        <div className="space-y-1">
                          {dep.vulnerabilities.map((v, j) => (
                            <div key={j} className="rounded border border-ink-700/40 bg-ink-850/50 p-2 text-xs">
                              <div className="flex items-center gap-2">
                                {v.cve && <span className="font-mono text-danger">{v.cve}</span>}
                                <span className="chip border border-ink-700/60 bg-ink-800/60 text-ink-400">{v.severity}</span>
                                {v.fixed_in && <span className="text-volt-300">Fixed in {v.fixed_in}</span>}
                              </div>
                              {v.description && <p className="mt-1 text-ink-400">{v.description}</p>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {dep.poisoning_indicators && dep.poisoning_indicators.length > 0 && (
                      <div className="mb-3">
                        <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1.5 flex items-center gap-1">
                          <Skull className="h-3 w-3" /> Poisoning Indicators
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {dep.poisoning_indicators.map((p, j) => (
                            <span key={j} className="chip border border-danger/30 bg-danger/10 text-danger text-[10px]">{p}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    {dep.behavioral_fingerprint && (
                      <div className="mb-3">
                        <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1.5 flex items-center gap-1">
                          <Activity className="h-3 w-3" /> Behavioral Fingerprint
                        </p>
                        <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
                          {Object.entries(dep.behavioral_fingerprint).map(([key, val]) => (
                            <div key={key} className="rounded border border-ink-700/40 bg-ink-850/50 p-2">
                              <p className="text-[10px] uppercase tracking-wider text-ink-500">{key}</p>
                              <p className="mt-0.5 text-ink-300">{Array.isArray(val) ? val.length : 0} signals</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {dep.blast_radius && (
                      <div className="rounded-lg border border-ink-700/40 bg-ink-950/40 p-3">
                        <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1">Blast Radius</p>
                        <p className="text-sm text-ink-300">{dep.blast_radius.scope}</p>
                        {dep.blast_radius.affected_components && dep.blast_radius.affected_components.length > 0 && (
                          <div className="mt-1.5 flex flex-wrap gap-1.5">
                            {dep.blast_radius.affected_components.map((c, j) => (
                              <span key={j} className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400">{c}</span>
                            ))}
                          </div>
                        )}
                        {dep.blast_radius.data_exposure && (
                          <p className="mt-1.5 text-xs text-warning">Data exposure: {dep.blast_radius.data_exposure}</p>
                        )}
                      </div>
                    )}
                  </Panel>
                ))}
              </div>
            </>
          )}

          {!result && !loading && savedDeps.length > 0 && (
            <Panel className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-ink-100">Previously Scanned Dependencies</h3>
              <div className="space-y-2">
                {savedDeps.slice(0, 8).map((d) => (
                  <div key={d.id} className="flex items-center justify-between rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                    <div>
                      <p className="font-mono text-sm text-ink-100">{d.name}</p>
                      <p className="text-xs text-ink-500">{d.version} · {d.ecosystem}</p>
                    </div>
                    <RiskBadge risk={d.risk_level} />
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

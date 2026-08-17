import { useState } from "react";
import { Cpu, Loader2, AlertCircle, FileUp, Skull, Zap, GitCompareArrows } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { AIBinaryResult } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  EmptyState,
  StatCard,
  ClassificationTag,
  RiskBadge,
} from "@/components/ui-kit";
import { classNames, sha256 } from "@/lib/utils";

const SAMPLE_BINARY = `Binary: auth-service
Format: ELF x86-64
SHA256: a1b2c3d4e5f6...
Architecture: x86_64

Extracted strings:
- https://api.internal.auth/v1/tokens
- /etc/auth/credentials.key
- password
- SELECT * FROM users WHERE
- 10.0.0.5:3306
- Authorization: Bearer
- exec(/bin/sh)
- eval()

Imported functions:
- dlopen, dlsym (libdl)
- system, popen (libc)
- connect, send, recv (libsocket)
- fopen, fread, fwrite (libc)
- MD5, SHA1 (libcrypto)
- getaddrinfo (libresolv)

Exported functions:
- authenticate_user
- generate_token
- verify_signature
- load_credentials
- execute_query

Behavioral observations:
- Network: connects to 10.0.0.5:3306, sends credentials in plaintext
- Filesystem: reads /etc/auth/credentials.key
- Process: spawns child process via system()
- Crypto: uses MD5 and SHA1 (deprecated)`;

export function ReverseEngineeringPage() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIBinaryResult | null>(null);

  const handleAnalyze = async () => {
    if (!input.trim()) {
      setError("Please paste binary metadata (strings, imports, functions) or upload a metadata file.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const hash = await sha256(input);
      const { data: scanRow } = await supabase
        .from("scans")
        .insert({
          name: `Binary Analysis — ${new Date().toLocaleString()}`,
          scan_type: "binary",
          status: "running",
          input_hash: hash,
        })
        .select()
        .single();

      const res = await ai.reverseEngineer(input);
      setResult(res);

      if (scanRow) {
        await supabase.from("scans").update({ status: "completed", summary: res.summary as Record<string, unknown> }).eq("id", scanRow.id);
        await supabase.from("binary_analyses").insert({
          scan_id: scanRow.id,
          binary_name: res.summary?.format || "unknown",
          architecture: res.summary?.architecture || null,
          format: res.summary?.format || null,
          sha256: res.summary?.sha256 || null,
          strings: res.strings,
          imports: res.imports,
          functions: res.functions,
          suspicious_apis: res.suspicious_apis,
          behavior: res.behavior,
          behavioral_diff: res.behavioral_diff,
          integrity_mismatches: res.integrity_mismatches,
          summary: res.summary,
        });
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
    reader.onload = () => setInput(reader.result as string);
    reader.readAsText(file);
  };

  const riskLevel = (result?.summary?.risk_level as string) || "unknown";

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Reverse Engineering"
        subtitle="Analyze binaries with strings, imports, functions, behavior, suspicious APIs, and source→build→binary→runtime integrity mismatches."
        icon={<Cpu className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <div className="mb-3 flex items-center justify-between">
              <label className="label !mb-0">Binary Metadata</label>
              <div className="flex gap-2">
                <label className="btn-ghost !px-3 !py-1.5 !text-xs cursor-pointer">
                  <FileUp className="h-3.5 w-3.5" />
                  Upload
                  <input type="file" className="hidden" onChange={handleFile} accept=".txt,.json,.md" />
                </label>
                <button onClick={() => setInput(SAMPLE_BINARY)} className="btn-ghost !px-3 !py-1.5 !text-xs">
                  Sample
                </button>
              </div>
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Paste extracted strings, imports, exported functions, behavioral observations..."
              rows={16}
              className="textarea"
            />
            <p className="mt-2 text-xs text-ink-500">
              Note: AegisCode analyzes metadata extracted from binaries. Direct binary disassembly requires native tooling not available in-browser.
            </p>
            <Button onClick={handleAnalyze} disabled={loading || !input.trim()} className="mt-3 w-full" size="lg">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Cpu className="h-4 w-4" />}
              {loading ? "Analyzing Binary..." : "Analyze Binary"}
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
                <p className="mt-3 text-sm text-ink-300">Analyzing binary metadata...</p>
                <p className="mt-1 text-xs text-ink-500">Extracting indicators, identifying suspicious APIs, checking integrity</p>
              </div>
            </Panel>
          )}

          {!loading && !result && (
            <Panel className="p-8">
              <EmptyState
                icon={<Cpu className="h-12 w-12" />}
                title="No Analysis Yet"
                description="Paste binary metadata (strings, imports, functions) and run analysis. The engine identifies suspicious APIs, behavioral anomalies, and integrity mismatches."
              />
            </Panel>
          )}

          {result && (
            <>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <StatCard label="Format" value={(result.summary.format as string) || "—"} icon={<Cpu className="h-5 w-5" />} accent="cyber" />
                <StatCard label="Architecture" value={(result.summary.architecture as string) || "—"} accent="default" />
                <StatCard label="Risk Level" value={(result.summary.risk_level as string) || "unknown"} icon={<Skull className="h-5 w-5" />} accent="danger" />
                <StatCard label="Suspicious APIs" value={result.suspicious_apis?.length ?? 0} icon={<Zap className="h-5 w-5" />} accent="warning" />
              </div>

              {result.suspicious_apis && result.suspicious_apis.length > 0 && (
                <Panel className="p-5">
                  <h3 className="mb-3 text-sm font-semibold text-ink-100 flex items-center gap-2">
                    <Skull className="h-4 w-4 text-danger" /> Suspicious APIs
                  </h3>
                  <div className="space-y-2">
                    {result.suspicious_apis.map((api, i) => (
                      <div key={i} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono text-sm text-ink-100">{api.api}</span>
                          {api.risk && <RiskBadge risk={api.risk as never} />}
                        </div>
                        <p className="text-xs text-ink-400">{api.reason}</p>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              <div className="grid gap-4 sm:grid-cols-2">
                {result.strings && result.strings.length > 0 && (
                  <Panel className="p-5">
                    <h3 className="mb-3 text-sm font-semibold text-ink-100">Extracted Strings</h3>
                    <div className="max-h-64 space-y-1.5 overflow-y-auto">
                      {result.strings.map((s, i) => (
                        <div key={i} className="flex items-center justify-between rounded border border-ink-700/40 bg-ink-850/50 px-2 py-1.5">
                          <span className="font-mono text-xs text-ink-300 truncate">{s.value}</span>
                          {s.category && <span className="chip border border-ink-700/60 bg-ink-800/60 text-[9px] text-ink-500 shrink-0">{s.category}</span>}
                        </div>
                      ))}
                    </div>
                  </Panel>
                )}

                {result.imports && result.imports.length > 0 && (
                  <Panel className="p-5">
                    <h3 className="mb-3 text-sm font-semibold text-ink-100">Imports</h3>
                    <div className="max-h-64 space-y-1.5 overflow-y-auto">
                      {result.imports.map((imp, i) => (
                        <div key={i} className="flex items-center justify-between rounded border border-ink-700/40 bg-ink-850/50 px-2 py-1.5">
                          <div>
                            <span className="font-mono text-xs text-ink-300">{imp.name}</span>
                            {imp.library && <span className="ml-1.5 text-[10px] text-ink-500">({imp.library})</span>}
                          </div>
                          {imp.risk && <RiskBadge risk={imp.risk as never} />}
                        </div>
                      ))}
                    </div>
                  </Panel>
                )}
              </div>

              {result.behavior && Object.keys(result.behavior).length > 0 && (
                <Panel className="p-5">
                  <h3 className="mb-3 text-sm font-semibold text-ink-100">Behavioral Analysis</h3>
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {Object.entries(result.behavior).map(([key, val]) => (
                      <div key={key} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                        <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 capitalize">{key}</p>
                        {Array.isArray(val) && val.length > 0 ? (
                          <ul className="mt-1.5 space-y-0.5">
                            {val.map((v, i) => (
                              <li key={i} className="text-xs text-ink-300 font-mono">{v}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="mt-1 text-xs text-ink-500">No signals</p>
                        )}
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {result.integrity_mismatches && result.integrity_mismatches.length > 0 && (
                <Panel className="p-5">
                  <h3 className="mb-3 text-sm font-semibold text-ink-100 flex items-center gap-2">
                    <GitCompareArrows className="h-4 w-4 text-warning" /> Integrity Mismatches
                  </h3>
                  <div className="space-y-2">
                    {result.integrity_mismatches.map((m, i) => (
                      <div key={i} className="rounded-lg border border-warning/20 bg-warning/5 p-3">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-ink-100">{m.type}</span>
                          <div className="flex items-center gap-2">
                            {m.severity && <RiskBadge risk={m.severity as never} />}
                            {m.classification && <ClassificationTag classification={m.classification} />}
                          </div>
                        </div>
                        <p className="text-xs text-ink-400">{m.description}</p>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

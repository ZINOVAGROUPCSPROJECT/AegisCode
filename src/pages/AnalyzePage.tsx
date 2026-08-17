import { useState } from "react";
import {
  ScanSearch,
  Loader2,
  AlertCircle,
  ShieldAlert,
  Code2,
  FileUp,
  Sparkles,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Crosshair,
  Wrench,
} from "lucide-react";
import { ai } from "@/lib/ai";
import { supabase } from "@/lib/db";
import type { AICodeAnalysisResult, AIFinding, Scan } from "@/lib/types";
import {
  Panel,
  Button,
  SeverityBadge,
  ClassificationTag,
  ExploitabilityBadge,
  CvssScore,
  KevBadge,
  CodeBlock,
  EmptyState,
  PageHeader,
} from "@/components/ui-kit";
import { classNames, sha256, countLines, severityRank } from "@/lib/utils";
import type { PageId } from "@/components/AppShell";

const SAMPLE_CODE = `const express = require('express');
const mysql = require('mysql2');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  connection.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get('/search', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Results for ' + name + '</h1>');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const token = Buffer.from(username + ':' + password).toString('base64');
  res.cookie('session', token, { httpOnly: false });
  res.json({ success: true });
});

app.listen(3000);`;

export function AnalyzePage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("auto");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AICodeAnalysisResult | null>(null);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!code.trim()) {
      setError("Please paste or upload code to analyze.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    setScanId(null);

    try {
      const hash = await sha256(code);
      const loc = countLines(code);

      const { data: scanRow } = await supabase
        .from("scans")
        .insert({
          name: `Code Analysis — ${new Date().toLocaleString()}`,
          scan_type: "code",
          status: "running",
          language: language === "auto" ? null : language,
          input_hash: hash,
          loc,
          model: "openrouter/auto",
        })
        .select()
        .single();

      const analysis = await ai.analyzeCode(code, language === "auto" ? undefined : language);
      setResult(analysis);

      if (scanRow) {
        setScanId(scanRow.id);
        await supabase
          .from("scans")
          .update({
            status: "completed",
            summary: analysis.summary as Record<string, unknown>,
          })
          .eq("id", scanRow.id);

        const findings = (analysis.findings || []).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
        if (findings.length > 0 && scanRow.id) {
          const rows = findings.map((f) => ({
            scan_id: scanRow.id,
            title: f.title,
            description: f.description,
            severity: f.severity,
            cwe: f.cwe || null,
            cwe_url: null,
            cvss_score: f.cvss_score ?? null,
            cvss_vector: f.cvss_vector || null,
            epss_score: null,
            epss_percentile: null,
            in_kev: false,
            location: f.location || null,
            file_path: f.file_path || null,
            line_start: f.line_start ?? null,
            line_end: f.line_end ?? null,
            evidence: f.evidence as never,
            evidence_chain: f.evidence_chain as never,
            remediation: f.remediation || null,
            secure_fix: f.secure_fix || null,
            reachability: f.reachability,
            exploitability: f.exploitability,
            exploit_confidence: f.exploit_confidence ?? 0,
            attack_paths: f.attack_paths as never,
            data_flow: f.data_flow as never,
            verdict: f.verdict as never,
            verified_gone: false,
            status: "open" as const,
          }));
          await supabase.from("findings").insert(rows as never);
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      if (scanId) {
        await supabase.from("scans").update({ status: "failed" }).eq("id", scanId);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setCode(reader.result as string);
      const ext = file.name.split(".").pop()?.toLowerCase();
      if (ext) setLanguage(ext);
    };
    reader.readAsText(file);
  };

  const sortedFindings = result?.findings
    ? [...result.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    : [];

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="AI Code Security Analyzer"
        subtitle="Upload or paste code — get vulnerability detection with CWE, evidence, exploitability verdict, and secure fixes."
        icon={<ScanSearch className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        {/* Input panel */}
        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <div className="mb-3 flex items-center justify-between">
              <label className="label !mb-0">Source Code</label>
              <div className="flex gap-2">
                <label className="btn-ghost !px-3 !py-1.5 !text-xs cursor-pointer">
                  <FileUp className="h-3.5 w-3.5" />
                  Upload
                  <input type="file" className="hidden" onChange={handleFileUpload} accept=".js,.ts,.tsx,.py,.java,.go,.rs,.c,.cpp,.php,.rb,.cs,.html,.xml,.json,.yaml,.yml,.sh,.sql" />
                </label>
                <button
                  onClick={() => setCode(SAMPLE_CODE)}
                  className="btn-ghost !px-3 !py-1.5 !text-xs"
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  Sample
                </button>
              </div>
            </div>
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Paste your source code here..."
              rows={16}
              className="textarea"
            />
            <div className="mt-2 flex items-center justify-between text-xs text-ink-500">
              <span>{countLines(code)} lines</span>
              <span>{code.length} chars</span>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3">
              <div>
                <label className="label">Language</label>
                <select value={language} onChange={(e) => setLanguage(e.target.value)} className="input">
                  <option value="auto">Auto-detect</option>
                  <option value="javascript">JavaScript</option>
                  <option value="typescript">TypeScript</option>
                  <option value="python">Python</option>
                  <option value="java">Java</option>
                  <option value="go">Go</option>
                  <option value="rust">Rust</option>
                  <option value="c">C/C++</option>
                  <option value="php">PHP</option>
                  <option value="ruby">Ruby</option>
                  <option value="csharp">C#</option>
                </select>
              </div>
              <div>
                <label className="label">AI Model</label>
                <div className="input flex items-center justify-between opacity-70">
                  <span className="text-ink-300">openrouter/auto</span>
                  <span className="text-xs text-ink-500">Locked</span>
                </div>
              </div>
            </div>

            <Button onClick={handleAnalyze} disabled={loading || !code.trim()} className="mt-4 w-full" size="lg">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}
              {loading ? "Analyzing..." : "Run Security Analysis"}
            </Button>

            {error && (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </Panel>

          {/* Analysis guidelines */}
          <Panel className="p-5">
            <h3 className="mb-3 text-sm font-semibold text-ink-100">How AegisCode Analyzes</h3>
            <ul className="space-y-2 text-xs text-ink-400">
              <li className="flex gap-2"><CheckCircle2 className="h-4 w-4 text-volt-400 shrink-0" /> Identifies vulnerabilities with CWE mapping and CVSS scoring</li>
              <li className="flex gap-2"><CheckCircle2 className="h-4 w-4 text-volt-400 shrink-0" /> Assesses application-aware exploitability — not just "vulnerable"</li>
              <li className="flex gap-2"><CheckCircle2 className="h-4 w-4 text-volt-400 shrink-0" /> Builds evidence chain: CVE → dependency → function → data flow → endpoint → attack path → impact</li>
              <li className="flex gap-2"><CheckCircle2 className="h-4 w-4 text-volt-400 shrink-0" /> Every result tagged: OBSERVED / VERIFIED / INFERRED / UNKNOWN</li>
              <li className="flex gap-2"><CheckCircle2 className="h-4 w-4 text-volt-400 shrink-0" /> Generates secure fix code for each finding</li>
              <li className="flex gap-2"><AlertCircle className="h-4 w-4 text-warning shrink-0" /> Never claims 100% safe — never fabricates evidence</li>
            </ul>
          </Panel>
        </div>

        {/* Results panel */}
        <div className="lg:col-span-3 space-y-4">
          {loading && (
            <Panel className="p-8 scanline">
              <div className="flex flex-col items-center text-center">
                <Loader2 className="h-8 w-8 animate-spin text-cyber-400" />
                <p className="mt-3 text-sm text-ink-300">Running AI security analysis...</p>
                <p className="mt-1 text-xs text-ink-500">Detecting vulnerabilities, evaluating exploitability, building evidence chains</p>
              </div>
            </Panel>
          )}

          {!loading && !result && (
            <Panel className="p-8">
              <EmptyState
                icon={<Code2 className="h-12 w-12" />}
                title="Awaiting Analysis"
                description="Paste code on the left and run a security analysis. Results will appear here with severity, CWE, evidence, and exploitability verdicts."
              />
            </Panel>
          )}

          {result && (
            <>
              {/* Summary */}
              <Panel className="p-5">
                <div className="mb-4 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-ink-100">Analysis Summary</h3>
                  <span className="text-xs text-ink-500 font-mono">
                    {result.summary.loc} LOC · {result.summary.language}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
                  {[
                    { label: "Total", value: result.summary.total, color: "text-ink-100" },
                    { label: "Critical", value: result.summary.critical, color: "text-danger" },
                    { label: "High", value: result.summary.high, color: "text-orange-400" },
                    { label: "Medium", value: result.summary.medium, color: "text-warning" },
                    { label: "Low", value: result.summary.low, color: "text-cyber-300" },
                    { label: "Info", value: result.summary.info, color: "text-ink-400" },
                  ].map((s) => (
                    <div key={s.label} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3 text-center">
                      <p className={classNames("text-2xl font-bold font-mono", s.color)}>{s.value}</p>
                      <p className="mt-0.5 text-[10px] uppercase tracking-wider text-ink-500">{s.label}</p>
                    </div>
                  ))}
                </div>
              </Panel>

              {/* Findings */}
              {sortedFindings.length === 0 ? (
                <Panel className="p-6">
                  <div className="flex items-center gap-3 text-volt-300">
                    <CheckCircle2 className="h-6 w-6" />
                    <div>
                      <p className="font-semibold">No vulnerabilities detected in this analysis.</p>
                      <p className="text-xs text-ink-400 mt-0.5">This does not guarantee the code is safe — analysis is not exhaustive.</p>
                    </div>
                  </div>
                </Panel>
              ) : (
                <div className="space-y-3">
                  {sortedFindings.map((finding, i) => (
                    <FindingCard
                      key={i}
                      finding={finding}
                      expanded={expandedFinding === i}
                      onToggle={() => setExpandedFinding(expandedFinding === i ? null : i)}
                      onRemediate={() => onNavigate("remediation")}
                      onExploitability={() => onNavigate("exploitability")}
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}


function FindingCard({
  finding,
  expanded,
  onToggle,
  onRemediate,
  onExploitability,
}: {
  finding: AIFinding;
  expanded: boolean;
  onToggle: () => void;
  onRemediate: () => void;
  onExploitability: () => void;
}) {
  return (
    <Panel className="overflow-hidden">
      <div onClick={onToggle} className="cursor-pointer p-4 transition-colors hover:bg-ink-850/50">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ExploitabilityBadge exploitability={finding.exploitability} />
              {finding.cwe && (
                <span className="chip border border-ink-700/60 bg-ink-800/60 font-mono text-ink-300">
                  {finding.cwe}
                </span>
              )}
              <span className="flex items-center gap-1 text-xs text-ink-500">
                <Crosshair className="h-3 w-3" />
                {finding.exploit_confidence}% confidence
              </span>
            </div>
            <h4 className="mt-2 text-sm font-semibold text-ink-100">{finding.title}</h4>
            <p className="mt-0.5 text-xs text-ink-400">{finding.location}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <div className="text-right">
              <p className="text-[10px] uppercase tracking-wider text-ink-500">CVSS</p>
              <CvssScore score={finding.cvss_score} />
            </div>
            {expanded ? <ChevronDown className="h-4 w-4 text-ink-500" /> : <ChevronRight className="h-4 w-4 text-ink-500" />}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-ink-700/60 p-4 space-y-4 animate-fade-in">
          {/* Description */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1">Description</p>
            <p className="text-sm text-ink-300">{finding.description}</p>
          </div>

          {/* Verdict */}
          {finding.verdict && (
            <div className="rounded-lg border border-ink-700/40 bg-ink-950/40 p-3">
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs font-semibold uppercase tracking-wider text-ink-500">Application-Aware Verdict</p>
                {finding.verdict.classification && <ClassificationTag classification={finding.verdict.classification as never} />}
              </div>
              <div className="flex items-center gap-3">
                <span
                  className={classNames(
                    "text-lg font-bold",
                    finding.verdict.exploitable_in_this_app ? "text-danger" : "text-volt-300"
                  )}
                >
                  {finding.verdict.exploitable_in_this_app ? "Exploitable in this app" : "Not exploitable in this app"}
                </span>
                <span className="text-xs text-ink-400">({finding.verdict.confidence ?? 0}% confidence)</span>
              </div>
              {finding.verdict.reasoning && (
                <p className="mt-1.5 text-sm text-ink-300">{finding.verdict.reasoning}</p>
              )}
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && finding.evidence.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Evidence</p>
              <div className="space-y-2">
                {finding.evidence.map((ev, i) => (
                  <div key={i} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-medium text-ink-300">{ev.type || "evidence"}</span>
                      {ev.classification && <ClassificationTag classification={ev.classification as never} />}
                    </div>
                    {ev.snippet && (
                      <pre className="mb-1.5 overflow-x-auto rounded bg-ink-950/60 p-2 font-mono text-xs text-ink-200">
                        {ev.snippet}
                      </pre>
                    )}
                    {ev.explanation && <p className="text-xs text-ink-400">{ev.explanation}</p>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Evidence chain */}
          {finding.evidence_chain && finding.evidence_chain.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Evidence Chain</p>
              <div className="space-y-1">
                {finding.evidence_chain.map((node, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyber-500/15 font-mono text-[10px] text-cyber-300">
                      {node.step}
                    </span>
                    <div className="flex-1">
                      <span className="font-medium text-ink-200">{node.node}</span>
                      {node.node_type && (
                        <span className="ml-1.5 chip border border-ink-700/60 bg-ink-800/60 text-[10px] text-ink-400">
                          {node.node_type}
                        </span>
                      )}
                      {node.classification && <ClassificationTag classification={node.classification as never} className="ml-1.5" />}
                      <p className="mt-0.5 text-ink-400">{node.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Data flow */}
          {finding.data_flow && finding.data_flow.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Data Flow</p>
              <div className="flex flex-wrap items-center gap-1.5">
                {finding.data_flow.map((df, i) => (
                  <div key={i} className="flex items-center gap-1.5">
                    <span className="rounded-md border border-ink-700/40 bg-ink-850/50 px-2 py-1 text-xs text-ink-300">
                      {df.point}
                    </span>
                    {i < finding.data_flow.length - 1 && <ChevronRight className="h-3 w-3 text-ink-600" />}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attack paths */}
          {finding.attack_paths && finding.attack_paths.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Attack Paths</p>
              <div className="space-y-2">
                {finding.attack_paths.map((path, i) => (
                  <div key={i} className="rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-ink-200">{path.name}</span>
                      <div className="flex items-center gap-2">
                        <span
                          className={classNames(
                            "chip border",
                            path.status === "validated"
                              ? "text-danger bg-danger/15 border-danger/30"
                              : path.status === "reachable"
                              ? "text-orange-400 bg-orange-500/15 border-orange-500/30"
                              : "text-warning bg-warning/15 border-warning/30"
                          )}
                        >
                          {path.status}
                        </span>
                        <span className="text-xs text-ink-500 font-mono">{path.confidence}%</span>
                      </div>
                    </div>
                    {Array.isArray(path.steps) && (
                      <ol className="mt-1.5 space-y-1">
                        {path.steps.map((step, j) => (
                          <li key={j} className="flex items-start gap-2 text-xs text-ink-400">
                            <span className="font-mono text-ink-600">{j + 1}.</span>
                            <span>{typeof step === "string" ? step : (step as { action?: string }).action || JSON.stringify(step)}</span>
                          </li>
                        ))}
                      </ol>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-1">Remediation</p>
              <p className="text-sm text-ink-300">{finding.remediation}</p>
            </div>
          )}

          {finding.secure_fix && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-500 mb-2">Secure Fix</p>
              <CodeBlock code={finding.secure_fix} language="secure code" />
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2 pt-2">
            <Button variant="ghost" size="sm" onClick={onExploitability}>
              <Crosshair className="h-3.5 w-3.5" />
              Deep Exploitability
            </Button>
            <Button variant="ghost" size="sm" onClick={onRemediate}>
              <Wrench className="h-3.5 w-3.5" />
              Remediate & Verify
            </Button>
          </div>
        </div>
      )}
    </Panel>
  );
}

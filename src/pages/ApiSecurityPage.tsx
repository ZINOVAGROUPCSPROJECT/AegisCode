import { useState, useEffect } from "react";
import { Plug, Loader2, AlertCircle, ShieldAlert, Lock, Unlock, FlaskConical } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { AIApiSecurityResult, ApiEndpointResult, RiskLevel } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  RiskBadge,
  SeverityBadge,
  ClassificationTag,
  EmptyState,
  StatCard,
} from "@/components/ui-kit";
import { classNames, sha256, countLines } from "@/lib/utils";

const SAMPLE = `// Express API routes
app.get('/api/users/:id', async (req, res) => {
  const user = await db.users.findById(req.params.id); // no ownership check
  res.json(user);
});

app.post('/api/admin/users', requireAuth, async (req, res) => {
  const created = await db.users.create(req.body); // mass assignment
  res.json(created);
});

app.get('/api/fetch', async (req, res) => {
  const r = await fetch(req.query.url);            // SSRF
  res.send(await r.text());
});

app.post('/api/login', async (req, res) => {
  const rows = await db.raw(\`SELECT * FROM users WHERE email='\${req.body.email}'\`);
  res.json({ token: sign(rows[0]) });              // injection, no rate limit
});`;

interface StoredEndpoint {
  id: string;
  method: string;
  path: string;
  risk_level: RiskLevel;
  auth_required: boolean;
  created_at: string;
}

export function ApiSecurityPage() {
  const [input, setInput] = useState("");
  const [uploadedName, setUploadedName] = useState<string | null>(null);
  const [appContext, setAppContext] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIApiSecurityResult | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [saved, setSaved] = useState<StoredEndpoint[]>([]);

  const loadSaved = async () => {
    const { data } = await supabase
      .from("api_endpoints")
      .select("id, method, path, risk_level, auth_required, created_at")
      .order("created_at", { ascending: false })
      .limit(25);
    setSaved((data as StoredEndpoint[]) ?? []);
  };

  useEffect(() => {
    void loadSaved();
  }, []);

  const handleScan = async () => {
    if (!input.trim()) {
      setError("Paste route code, an OpenAPI spec, or a list of endpoints to discover.");
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
          name: `API Security Scan — ${new Date().toLocaleString()}`,
          scan_type: "api_security",
          status: "running",
          input_hash: hash,
          loc: countLines(input),
        })
        .select()
        .single();

      const res = await ai.scanApis(input, appContext || "No additional context provided.");
      setResult(res);

      if (scanRow) {
        await supabase
          .from("scans")
          .update({ status: "completed", summary: res.summary as Record<string, unknown> })
          .eq("id", scanRow.id);
      }

      for (const ep of res.endpoints ?? []) {
        const { data: epRow } = await supabase
          .from("api_endpoints")
          .insert({
            scan_id: scanRow?.id ?? null,
            method: ep.method,
            path: ep.path,
            handler: ep.handler ?? null,
            auth_required: ep.auth_required ?? false,
            auth_mechanism: ep.auth_mechanism ?? null,
            exposure: ep.exposure ?? "unknown",
            parameters: ep.parameters ?? [],
            risks: ep.risks ?? [],
            risk_level: ep.risk_level ?? "unknown",
            notes: ep.notes ?? null,
          } as never)
          .select()
          .single();

        const tests = ep.tests ?? [];
        if (epRow && tests.length > 0) {
          await supabase.from("api_tests").insert(
            tests.map((t) => ({
              endpoint_id: (epRow as { id: string }).id,
              category: t.category,
              name: t.name,
              outcome: t.outcome,
              severity: t.severity ?? null,
              request_example: t.request_example ?? null,
              expected: t.expected ?? null,
              observed: t.observed ?? null,
              classification: t.classification ?? "inferred",
              remediation: t.remediation ?? null,
            })) as never,
          );
        }
      }
      await loadSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const endpointKey = (ep: ApiEndpointResult, i: number) => `${ep.method}-${ep.path}-${i}`;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="API Security"
        subtitle="Discover every endpoint, then test for broken auth, IDOR, injection, SSRF, mass assignment and data exposure."
        icon={<Plug className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <label className="label !mb-0">Routes / OpenAPI / Endpoint list</label>
              <div className="flex items-center gap-3">
                <label className="cursor-pointer text-xs text-cyber-300 transition-colors hover:text-cyber-200">
                  Upload API file
                  <input
                    type="file"
                    accept=".json,.yaml,.yml,.txt,.ts,.js,.py,.rb,.go,.java,.md"
                    className="hidden"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      const text = await file.text();
                      setInput(text.slice(0, 200_000));
                      setUploadedName(file.name);
                      e.target.value = "";
                    }}
                  />
                </label>
                <button
                  onClick={() => setInput(SAMPLE)}
                  className="text-xs text-cyber-300 hover:text-cyber-200 transition-colors"
                >
                  Load sample
                </button>
              </div>
            </div>
            {uploadedName && (
              <p className="mb-2 truncate text-[11px] text-ink-500">Loaded: {uploadedName}</p>
            )}

            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              spellCheck={false}
              placeholder="Paste route handlers, an OpenAPI/Swagger document, or a plain endpoint list…"
              className="input h-72 w-full resize-y font-mono text-[13px]"
            />
            <label className="label mt-4">Application context (optional)</label>
            <textarea
              value={appContext}
              onChange={(e) => setAppContext(e.target.value)}
              placeholder="Auth model, tenancy, gateway, rate limiting, who can reach what…"
              className="input h-24 w-full resize-y text-[13px]"
            />
            <Button onClick={handleScan} disabled={loading} className="mt-4 w-full">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" /> Discovering & testing…
                </span>
              ) : (
                "Discover & Test APIs"
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
            <p className="stat-label mb-3">Recently discovered</p>
            {saved.length === 0 ? (
              <p className="text-xs text-ink-500">No endpoints stored yet.</p>
            ) : (
              <ul className="space-y-2">
                {saved.map((ep) => (
                  <li key={ep.id} className="flex items-center justify-between gap-2 text-xs">
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="font-mono text-cyber-300">{ep.method}</span>
                      <span className="truncate font-mono text-ink-300">{ep.path}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      {ep.auth_required ? (
                        <Lock className="h-3 w-3 text-ok" />
                      ) : (
                        <Unlock className="h-3 w-3 text-warning" />
                      )}
                      <RiskBadge risk={ep.risk_level} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        <div className="lg:col-span-3 space-y-4">
          {!result && !loading && (
            <Panel className="p-10">
              <EmptyState
                icon={<Plug className="h-8 w-8" />}
                title="No API scan yet"
                description="AegisCode enumerates your API surface, classifies exposure and runs targeted authorization, injection and SSRF tests on each endpoint."
              />
            </Panel>
          )}

          {result && (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <StatCard label="Endpoints" value={result.summary?.total_endpoints ?? 0} accent="cyber" />
                <StatCard label="Unauthenticated" value={result.summary?.unauthenticated ?? 0} accent="warning" />
                <StatCard label="High risk" value={result.summary?.high_risk ?? 0} accent="danger" />
                <StatCard
                  label="Failed tests"
                  value={`${result.summary?.failed_tests ?? 0}/${result.summary?.tested ?? 0}`}
                  accent="volt"
                />
              </div>

              {(result.endpoints ?? []).map((ep, i) => {
                const key = endpointKey(ep, i);
                const open = expanded === key;
                return (
                  <Panel key={key} className="p-5">
                    <button
                      onClick={() => setExpanded(open ? null : key)}
                      className="flex w-full items-start justify-between gap-4 text-left"
                    >
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded skeu-bezel px-2 py-0.5 font-mono text-[11px] text-cyber-300">
                            {ep.method}
                          </span>
                          <span className="truncate font-mono text-sm text-ink-100">{ep.path}</span>
                          <RiskBadge risk={ep.risk_level ?? "unknown"} />
                        </div>
                        <p className="mt-1 text-xs text-ink-400">
                          {ep.auth_required
                            ? `Auth: ${ep.auth_mechanism || "required"}`
                            : "No authentication detected"}{" "}
                          · exposure {ep.exposure ?? "unknown"}
                          {ep.handler ? ` · ${ep.handler}` : ""}
                        </p>
                      </div>
                      <span className="shrink-0 text-xs text-ink-500">{open ? "Hide" : "Details"}</span>
                    </button>

                    {open && (
                      <div className="mt-4 space-y-4 border-t border-ink-800 pt-4">
                        {(ep.parameters ?? []).length > 0 && (
                          <div>
                            <p className="stat-label mb-2">Parameters</p>
                            <div className="flex flex-wrap gap-2">
                              {(ep.parameters ?? []).map((p, pi) => (
                                <span
                                  key={`${p.name}-${pi}`}
                                  className={classNames(
                                    "rounded-md skeu-bezel px-2 py-1 font-mono text-[11px]",
                                    p.user_controlled ? "text-warning" : "text-ink-300",
                                  )}
                                >
                                  {p.name}
                                  <span className="text-ink-500">:{p.location}</span>
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {(ep.risks ?? []).length > 0 && (
                          <div>
                            <p className="stat-label mb-2">Risks</p>
                            <ul className="space-y-2">
                              {(ep.risks ?? []).map((r, ri) => (
                                <li key={ri} className="rounded-lg skeu-screen p-3">
                                  <div className="flex items-center gap-2">
                                    <ShieldAlert className="h-3.5 w-3.5 text-danger" />
                                    <span className="text-xs font-semibold uppercase tracking-wider text-ink-200">
                                      {r.category.replace(/_/g, " ")}
                                    </span>
                                    <SeverityBadge severity={r.severity} />
                                    {r.classification && <ClassificationTag classification={r.classification} />}
                                  </div>
                                  <p className="mt-2 text-xs text-ink-300">{r.detail}</p>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {(ep.tests ?? []).length > 0 && (
                          <div>
                            <p className="stat-label mb-2">Security tests</p>
                            <ul className="space-y-2">
                              {(ep.tests ?? []).map((t, ti) => (
                                <li key={ti} className="rounded-lg skeu-screen p-3">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <FlaskConical className="h-3.5 w-3.5 text-cyber-300" />
                                    <span className="text-xs font-semibold text-ink-200">{t.name}</span>
                                    <span
                                      className={classNames(
                                        "rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                                        t.outcome === "vulnerable"
                                          ? "bg-danger/15 text-danger"
                                          : t.outcome === "safe"
                                            ? "bg-ok/15 text-ok"
                                            : "bg-ink-800 text-ink-400",
                                      )}
                                    >
                                      {t.outcome}
                                    </span>
                                    {t.severity && <SeverityBadge severity={t.severity} />}
                                    {t.classification && <ClassificationTag classification={t.classification} />}
                                  </div>
                                  {t.request_example && (
                                    <pre className="mt-2 overflow-x-auto font-mono text-[11px] text-ink-300">
                                      {t.request_example}
                                    </pre>
                                  )}
                                  {t.observed && (
                                    <p className="mt-2 text-xs text-ink-400">
                                      <span className="text-ink-500">Observed: </span>
                                      {t.observed}
                                    </p>
                                  )}
                                  {t.remediation && (
                                    <p className="mt-1 text-xs text-cyber-200">{t.remediation}</p>
                                  )}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {ep.notes && <p className="text-xs text-ink-400">{ep.notes}</p>}
                      </div>
                    )}
                  </Panel>
                );
              })}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

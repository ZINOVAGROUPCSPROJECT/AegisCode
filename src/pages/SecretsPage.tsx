import { useState, useEffect } from "react";
import { KeyRound, Loader2, AlertCircle, EyeOff, RotateCcw, Trash2 } from "lucide-react";
import { supabase } from "@/lib/db";
import { ai } from "@/lib/ai";
import type { AISecretScanResult, Severity, SecretValidity } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  SeverityBadge,
  ClassificationTag,
  EmptyState,
  StatCard,
} from "@/components/ui-kit";
import { classNames, sha256, countLines } from "@/lib/utils";

const SAMPLE = `# .env.production
DATABASE_URL=postgres://admin:S3cr3tP@ss@db.prod.internal:5432/app
STRIPE_SECRET_KEY=sk_live_51H9x8kLmNoPqRsTuVwXyZ0123456789abcdef
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SIGNING_SECRET=dev-secret
GITHUB_TOKEN=ghp_16CharsHereAndMoreCharsHere1234567
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1sample...
-----END RSA PRIVATE KEY-----`;

interface SecretRow {
  id: string;
  secret_type: string;
  provider: string | null;
  severity: Severity;
  masked_value: string | null;
  location: string | null;
  validity: SecretValidity;
  status: string;
  created_at: string;
}

const VALIDITY_STYLE: Record<string, string> = {
  likely_live: "bg-danger/15 text-danger",
  likely_test: "bg-warning/15 text-warning",
  revoked: "bg-ok/15 text-ok",
  unknown: "bg-ink-800 text-ink-400",
};

export function SecretsPage() {
  const [content, setContent] = useState("");
  const [source, setSource] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AISecretScanResult | null>(null);
  const [rows, setRows] = useState<SecretRow[]>([]);

  const load = async () => {
    const { data } = await supabase
      .from("secret_findings")
      .select("id, secret_type, provider, severity, masked_value, location, validity, status, created_at")
      .order("created_at", { ascending: false })
      .limit(50);
    setRows((data as SecretRow[]) ?? []);
  };

  useEffect(() => {
    void load();
  }, []);

  const handleScan = async () => {
    if (!content.trim()) {
      setError("Paste the file, config, or log content you want scanned for credentials.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const hash = await sha256(content);
      const { data: scanRow } = await supabase
        .from("scans")
        .insert({
          name: `Secret Scan — ${new Date().toLocaleString()}`,
          scan_type: "secrets",
          status: "running",
          input_hash: hash,
          loc: countLines(content),
        })
        .select()
        .single();

      const res = await ai.detectSecrets(content, source || "unspecified source");
      setResult(res);

      if (scanRow) {
        await supabase
          .from("scans")
          .update({ status: "completed", summary: res.summary as Record<string, unknown> })
          .eq("id", scanRow.id);
      }

      const secrets = res.secrets ?? [];
      if (secrets.length > 0) {
        await supabase.from("secret_findings").insert(
          secrets.map((s) => ({
            scan_id: scanRow?.id ?? null,
            secret_type: s.secret_type,
            provider: s.provider ?? null,
            severity: s.severity,
            masked_value: s.masked_value,
            location: s.location ?? source ?? null,
            line_start: s.line_start ?? null,
            entropy: s.entropy ?? null,
            validity: s.validity ?? "unknown",
            classification: s.classification ?? "observed",
            impact: s.impact ?? null,
            remediation: s.remediation ?? null,
            rotation_steps: s.rotation_steps ?? [],
            status: "open",
          })) as never,
        );
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const setStatus = async (id: string, status: string) => {
    await supabase.from("secret_findings").update({ status }).eq("id", id);
    await load();
  };

  const remove = async (id: string) => {
    await supabase.from("secret_findings").delete().eq("id", id);
    await load();
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Secret Detection"
        subtitle="Detect exposed API keys, tokens, passwords, private keys and connection strings — values are always masked."
        icon={<KeyRound className="h-6 w-6" />}
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <label className="label">Source label</label>
            <input
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder=".env.production / ci-config.yml / build log"
              className="input w-full font-mono text-[13px]"
            />
            <div className="mb-2 mt-4 flex items-center justify-between">
              <label className="label !mb-0">Content to scan</label>
              <button
                onClick={() => {
                  setSource(source || ".env.production");
                  setContent(SAMPLE);
                }}
                className="text-xs text-cyber-300 hover:text-cyber-200 transition-colors"
              >
                Load sample
              </button>
            </div>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              spellCheck={false}
              placeholder="Paste config, source, CI definition, or log output…"
              className="input h-72 w-full resize-y font-mono text-[13px]"
            />
            <p className="mt-2 flex items-center gap-1.5 text-[11px] text-ink-500">
              <EyeOff className="h-3 w-3" /> Detected values are stored masked, never in full.
            </p>
            <Button onClick={handleScan} disabled={loading} className="mt-4 w-full">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" /> Scanning for secrets…
                </span>
              ) : (
                "Scan for Secrets"
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
          {result && (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <StatCard label="Secrets" value={result.summary?.total ?? 0} accent="cyber" />
              <StatCard label="Critical" value={result.summary?.critical ?? 0} accent="danger" />
              <StatCard label="High" value={result.summary?.high ?? 0} accent="warning" />
              <StatCard label="Likely live" value={result.summary?.verified_live ?? 0} accent="volt" />
            </div>
          )}

          {rows.length === 0 && !result ? (
            <Panel className="p-10">
              <EmptyState
                icon={<KeyRound className="h-8 w-8" />}
                title="No secrets detected yet"
                description="Scan configuration files, source code, CI definitions or logs. AegisCode classifies each hit by provider, severity, entropy and likely validity, and gives rotation steps."
              />
            </Panel>
          ) : (
            <Panel className="p-5">
              <p className="stat-label mb-3">Detected secrets</p>
              <ul className="space-y-3">
                {rows.map((r) => (
                  <li key={r.id} className="rounded-lg skeu-screen p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={r.severity} />
                      <span className="text-sm font-semibold text-ink-100">{r.secret_type}</span>
                      {r.provider && <span className="text-xs text-ink-400">{r.provider}</span>}
                      <span
                        className={classNames(
                          "rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                          VALIDITY_STYLE[r.validity] ?? VALIDITY_STYLE["unknown"],
                        )}
                      >
                        {r.validity.replace("_", " ")}
                      </span>
                      {r.status !== "open" && (
                        <span className="rounded bg-ok/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-ok">
                          {r.status}
                        </span>
                      )}
                    </div>
                    <p className="mt-2 font-mono text-[12px] text-ink-300">{r.masked_value}</p>
                    {r.location && <p className="mt-1 text-xs text-ink-500">{r.location}</p>}
                    <div className="mt-3 flex flex-wrap gap-2">
                      {r.status === "open" && (
                        <Button size="sm" variant="ghost" onClick={() => void setStatus(r.id, "rotated")}>
                          <span className="flex items-center gap-1.5">
                            <RotateCcw className="h-3 w-3" /> Mark rotated
                          </span>
                        </Button>
                      )}
                      <Button size="sm" variant="danger" onClick={() => void remove(r.id)}>
                        <span className="flex items-center gap-1.5">
                          <Trash2 className="h-3 w-3" /> Delete
                        </span>
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          {(result?.secrets ?? []).length > 0 && (
            <Panel className="p-5">
              <p className="stat-label mb-3">Rotation guidance from this scan</p>
              <ul className="space-y-3">
                {(result?.secrets ?? []).map((s, i) => (
                  <li key={i} className="rounded-lg skeu-screen p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={s.severity} />
                      <span className="text-sm font-semibold text-ink-100">{s.secret_type}</span>
                      {s.classification && <ClassificationTag classification={s.classification} />}
                    </div>
                    {s.impact && <p className="mt-2 text-xs text-ink-300">{s.impact}</p>}
                    {s.remediation && <p className="mt-1 text-xs text-cyber-200">{s.remediation}</p>}
                    {(s.rotation_steps ?? []).length > 0 && (
                      <ol className="mt-2 space-y-1 text-xs text-ink-300">
                        {(s.rotation_steps ?? []).map((step, si) => (
                          <li key={si} className="flex gap-2">
                            <span className="font-mono text-ink-500">{si + 1}.</span>
                            <span>{step}</span>
                          </li>
                        ))}
                      </ol>
                    )}
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

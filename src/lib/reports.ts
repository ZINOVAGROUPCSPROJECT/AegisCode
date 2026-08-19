/**
 * Shared "save this analysis to Reports" helper.
 *
 * Every analysis surface (API security, DAST, drift, attack paths, ...) writes
 * its result into the same `reports` table so the Reports page can list,
 * download and delete them uniformly.
 */
import { supabase } from "@/lib/db";

export type AnalysisKind =
  | "code-analysis"
  | "api-security"
  | "dast"
  | "drift"
  | "attack-paths"
  | "exploitability"
  | "supply-chain"
  | "secrets"
  | "ci-cd"
  | "reverse-engineering"
  | "repo-scan";

export const ANALYSIS_LABEL: Record<AnalysisKind, string> = {
  "code-analysis": "Code Analysis",
  "api-security": "API Security",
  dast: "DAST / Runtime Testing",
  drift: "Security Drift",
  "attack-paths": "Attack Paths",
  exploitability: "Exploitability",
  "supply-chain": "Supply Chain",
  secrets: "Secret Scan",
  "ci-cd": "CI/CD Gate",
  "reverse-engineering": "Binary Analysis",
  "repo-scan": "Repository Scan",
};

function countBySeverity(value: unknown): Record<string, number> {
  const counts: Record<string, number> = {};
  const walk = (node: unknown, depth: number) => {
    if (!node || depth > 4) return;
    if (Array.isArray(node)) {
      node.forEach((item) => walk(item, depth + 1));
      return;
    }
    if (typeof node !== "object") return;
    const record = node as Record<string, unknown>;
    const severity = record["severity"];
    if (typeof severity === "string") counts[severity] = (counts[severity] ?? 0) + 1;
    Object.values(record).forEach((item) => walk(item, depth + 1));
  };
  walk(value, 0);
  return counts;
}

export interface SaveAnalysisInput {
  kind: AnalysisKind;
  title?: string;
  data: unknown;
  scanIds?: string[];
  /** Extra summary fields merged on top of the derived severity counts. */
  summary?: Record<string, unknown>;
}

export async function saveAnalysisReport({
  kind,
  title,
  data,
  scanIds = [],
  summary = {},
}: SaveAnalysisInput) {
  if (data === null || data === undefined) {
    throw new Error("Nothing to save — run the analysis first.");
  }
  const generatedAt = new Date().toISOString();
  const payload = {
    title: title || `${ANALYSIS_LABEL[kind]} — ${new Date(generatedAt).toLocaleString()}`,
    scan_ids: scanIds,
    summary: {
      kind,
      label: ANALYSIS_LABEL[kind],
      generated_at: generatedAt,
      severity_counts: countBySeverity(data),
      ...summary,
    },
    content: { kind, label: ANALYSIS_LABEL[kind], generated_at: generatedAt, result: data },
    format: "json",
  };

  const { data: row, error } = await supabase.from("reports").insert(payload).select().single();
  if (error) throw new Error(error.message);
  return row;
}
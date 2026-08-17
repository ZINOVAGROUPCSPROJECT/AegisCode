/**
 * Orchestration for the deterministic engines. Runs on the server so repository
 * downloads, OSV/EPSS lookups and DAST probes happen outside the browser.
 */
import { fetchRepoSnapshot, parseRepoInput, osvQuery, epssQuery, type RepoRef } from "./repo.server";
import { runSast, type SastFinding } from "./sast";
import { parseManifest, severityFromCvss, type DepVulnerability, type SbomComponent } from "./sbom";

export interface RepoScanPayload {
  repo: string;
  provider?: "github" | "gitlab" | undefined;
  ref?: string | undefined;
  token?: string | undefined;
}

export interface RepoScanResult {
  label: string;
  provider: string;
  ref: string;
  commitSha: string;
  filesScanned: number;
  linesScanned: number;
  filesDiscovered: number;
  truncated: boolean;
  findings: SastFinding[];
  summary: ReturnType<typeof runSast>["summary"];
  manifests: { path: string; content: string }[];
  languages: { language: string; files: number }[];
}

const LANG_BY_EXT: Record<string, string> = {
  ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript", mjs: "JavaScript", cjs: "JavaScript",
  py: "Python", rb: "Ruby", php: "PHP", go: "Go", java: "Java", kt: "Kotlin", cs: "C#", rs: "Rust",
  swift: "Swift", scala: "Scala", sql: "SQL", sh: "Shell", bash: "Shell", yml: "YAML", yaml: "YAML",
  json: "JSON", toml: "TOML", tf: "Terraform", html: "HTML", vue: "Vue", svelte: "Svelte", xml: "XML",
};

export async function scanRepository(payload: RepoScanPayload): Promise<RepoScanResult> {
  const parsed = parseRepoInput(payload.repo, payload.token);
  const ref: RepoRef = {
    ...parsed,
    ...(payload.provider ? { provider: payload.provider } : {}),
    ...(payload.ref ? { ref: payload.ref } : {}),
  };
  const snapshot = await fetchRepoSnapshot(ref);
  const sast = runSast(snapshot.files);

  const langCount = new Map<string, number>();
  for (const f of snapshot.files) {
    const e = f.path.split(".").pop()?.toLowerCase() ?? "";
    const lang = LANG_BY_EXT[e];
    if (lang) langCount.set(lang, (langCount.get(lang) ?? 0) + 1);
  }

  return {
    label: snapshot.label,
    provider: snapshot.provider,
    ref: snapshot.ref,
    commitSha: snapshot.commitSha,
    filesScanned: sast.filesScanned,
    linesScanned: sast.linesScanned,
    filesDiscovered: snapshot.totalFiles,
    truncated: snapshot.truncated,
    findings: sast.findings,
    summary: sast.summary,
    manifests: snapshot.manifests.map((m) => ({ path: m.path, content: m.content.slice(0, 120_000) })),
    languages: [...langCount.entries()]
      .map(([language, files]) => ({ language, files }))
      .sort((a, b) => b.files - a.files),
  };
}

export interface ScaPayload {
  manifests: { path: string; content: string }[];
}

export interface ScaResult {
  components: SbomComponent[];
  vulnerabilities: Record<string, DepVulnerability[]>;
  epss: Record<string, { score: number; percentile: number }>;
}

function cvssFromOsv(sev?: { type: string; score: string }[]): number | null {
  const vector = sev?.find((s) => s.type.startsWith("CVSS"))?.score;
  if (!vector) return null;
  const numeric = Number(vector);
  if (!Number.isNaN(numeric)) return numeric;
  // Approximate a base score from the vector's impact metrics when only a
  // vector string is published, so ranking still has a numeric signal.
  const av = /AV:([NALP])/.exec(vector)?.[1];
  const impacts = (vector.match(/[CIA]:([HLN])/g) ?? []).map((m) => m.split(":")[1]);
  const high = impacts.filter((i) => i === "H").length;
  const low = impacts.filter((i) => i === "L").length;
  let score = 2 + high * 2.2 + low * 1.1 + (av === "N" ? 2 : av === "A" ? 1 : 0);
  if (/PR:N/.test(vector)) score += 0.6;
  if (/UI:N/.test(vector)) score += 0.4;
  return Math.min(10, Math.round(score * 10) / 10);
}

export async function analyzeDependencies(payload: ScaPayload): Promise<ScaResult> {
  const components: SbomComponent[] = [];
  for (const m of payload.manifests) components.push(...parseManifest(m.path, m.content));

  const seen = new Map<string, SbomComponent>();
  for (const c of components) {
    const key = `${c.ecosystem}|${c.name}`;
    if (!seen.has(key)) seen.set(key, c);
  }
  const unique = [...seen.values()];

  const osv = await osvQuery(unique.map((c) => ({ name: c.name, version: c.version, ecosystem: c.ecosystem })));

  const vulnerabilities: Record<string, DepVulnerability[]> = {};
  const cves: string[] = [];
  for (const [key, vulns] of Object.entries(osv)) {
    vulnerabilities[key] = vulns.map((v) => {
      const cvss = cvssFromOsv(v.severity);
      const aliases = v.aliases ?? [];
      const cve = [v.id, ...aliases].find((a) => /^CVE-/i.test(a))?.toUpperCase() ?? null;
      if (cve) cves.push(cve);
      const fixed =
        v.affected?.flatMap((a) => a.ranges?.flatMap((r) => r.events?.map((e) => e.fixed) ?? []) ?? [])
          .filter((f): f is string => !!f)[0] ?? null;
      const dbSeverity = (v.database_specific?.severity ?? "").toLowerCase();
      return {
        id: v.id,
        aliases,
        cve,
        summary: v.summary || v.details?.slice(0, 240) || "Advisory published without a summary.",
        severity:
          (["critical", "high", "medium", "moderate", "low"].includes(dbSeverity)
            ? ((dbSeverity === "moderate" ? "medium" : dbSeverity) as DepVulnerability["severity"])
            : severityFromCvss(cvss)),
        cvss,
        fixedVersion: fixed,
        published: v.published ?? null,
        reference: `https://osv.dev/vulnerability/${v.id}`,
      };
    });
  }

  const epss = await epssQuery(cves);
  return { components: unique, vulnerabilities, epss };
}

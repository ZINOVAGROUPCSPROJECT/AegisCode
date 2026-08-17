/**
 * Deterministic SCA / SBOM engine.
 *
 * Manifests are parsed into a component inventory, exported as CycloneDX 1.5,
 * and correlated against OSV (advisories), CISA KEV (known exploitation) and
 * EPSS (exploit probability) to produce an explainable priority ranking.
 */

export type Ecosystem = "npm" | "PyPI" | "Maven" | "Go" | "RubyGems" | "crates.io" | "NuGet" | "Packagist";

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  purl: string;
  scope: "runtime" | "development";
  declared: string;
  direct: boolean;
}

export interface DepVulnerability {
  id: string;
  aliases: string[];
  cve: string | null;
  summary: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss: number | null;
  fixedVersion: string | null;
  published: string | null;
  reference: string | null;
}

export interface CorrelatedComponent extends SbomComponent {
  vulnerabilities: DepVulnerability[];
  inKev: boolean;
  kevRansomware: boolean;
  epss: number | null;
  epssPercentile: number | null;
  maxCvss: number | null;
  priority: number;
  priorityFactors: { factor: string; contribution: number; detail: string }[];
  recommendedVersion: string | null;
}

const RANGE_CHARS = /^[\^~>=<\s v=]+|\s.*$/g;

function cleanVersion(raw: string): string {
  const v = raw.replace(RANGE_CHARS, "").trim();
  return /^\d/.test(v) ? v : raw.trim();
}

function purl(ecosystem: Ecosystem, name: string, version: string): string {
  const type = {
    npm: "npm",
    PyPI: "pypi",
    Maven: "maven",
    Go: "golang",
    RubyGems: "gem",
    "crates.io": "cargo",
    NuGet: "nuget",
    Packagist: "composer",
  }[ecosystem];
  return `pkg:${type}/${name}@${version}`;
}

/** Detects the manifest kind from filename + content and extracts components. */
export function parseManifest(filename: string, content: string): SbomComponent[] {
  const f = filename.toLowerCase();
  if (f.endsWith("package.json")) return parsePackageJson(content);
  if (f.endsWith("requirements.txt")) return parseRequirements(content);
  if (f === "pyproject.toml" || f.endsWith("/pyproject.toml")) return parsePyproject(content);
  if (f.endsWith("go.mod")) return parseGoMod(content);
  if (f.endsWith("gemfile") || f.endsWith("gemfile.lock")) return parseGemfile(content);
  if (f.endsWith("cargo.toml")) return parseCargo(content);
  if (f.endsWith("pom.xml")) return parsePom(content);
  if (f.endsWith("composer.json")) return parseComposer(content);
  // Fallback: try JSON then requirements-style lines.
  try {
    JSON.parse(content);
    return parsePackageJson(content);
  } catch {
    return parseRequirements(content);
  }
}

function comp(
  name: string,
  declared: string,
  ecosystem: Ecosystem,
  scope: SbomComponent["scope"],
  direct = true,
): SbomComponent {
  const version = cleanVersion(declared);
  return { name, version, ecosystem, purl: purl(ecosystem, name, version), scope, declared, direct };
}

function parsePackageJson(content: string): SbomComponent[] {
  try {
    const json = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      packages?: Record<string, { version?: string; dev?: boolean }>;
    };
    const out: SbomComponent[] = [];
    for (const [name, v] of Object.entries(json.dependencies ?? {})) out.push(comp(name, v, "npm", "runtime"));
    for (const [name, v] of Object.entries(json.devDependencies ?? {}))
      out.push(comp(name, v, "npm", "development"));
    // package-lock.json v3 style
    for (const [path, meta] of Object.entries(json.packages ?? {})) {
      const name = path.replace(/^node_modules\//, "");
      if (!name || !meta.version) continue;
      out.push({
        ...comp(name, meta.version, "npm", meta.dev ? "development" : "runtime", false),
      });
    }
    return dedupe(out);
  } catch {
    return [];
  }
}

function parseRequirements(content: string): SbomComponent[] {
  const out: SbomComponent[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.split("#")[0]?.trim() ?? "";
    if (!line || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:[=<>~!]{1,2}\s*([0-9][^\s,;]*))?/);
    if (!m?.[1]) continue;
    out.push(comp(m[1], m[2] ?? "*", "PyPI", "runtime"));
  }
  return dedupe(out);
}

function parsePyproject(content: string): SbomComponent[] {
  const out: SbomComponent[] = [];
  const re = /^\s*([A-Za-z0-9._-]+)\s*=\s*["']([^"']+)["']/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content))) {
    if (["python", "name", "version", "description", "requires-python"].includes(m[1]!.toLowerCase())) continue;
    out.push(comp(m[1]!, m[2]!, "PyPI", "runtime"));
  }
  const arr = content.match(/dependencies\s*=\s*\[([^\]]*)\]/s)?.[1] ?? "";
  for (const item of arr.split(",")) {
    const s = item.replace(/["'\s]/g, "");
    if (!s) continue;
    const mm = s.match(/^([A-Za-z0-9._-]+)(?:[=<>~!]{1,2}([0-9][^\s,]*))?/);
    if (mm?.[1]) out.push(comp(mm[1], mm[2] ?? "*", "PyPI", "runtime"));
  }
  return dedupe(out);
}

function parseGoMod(content: string): SbomComponent[] {
  const out: SbomComponent[] = [];
  const re = /^\s*([a-z0-9./_-]+\.[a-z]{2,}[^\s]*)\s+(v[0-9][^\s]*)/gim;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content))) out.push(comp(m[1]!, m[2]!, "Go", "runtime"));
  return dedupe(out);
}

function parseGemfile(content: string): SbomComponent[] {
  const out: SbomComponent[] = [];
  const gem = /gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/g;
  let m: RegExpExecArray | null;
  while ((m = gem.exec(content))) out.push(comp(m[1]!, m[2] ?? "*", "RubyGems", "runtime"));
  const locked = /^\s{4}([a-z0-9._-]+)\s\(([^)]+)\)/gim;
  while ((m = locked.exec(content))) out.push(comp(m[1]!, m[2]!, "RubyGems", "runtime", false));
  return dedupe(out);
}

function parseCargo(content: string): SbomComponent[] {
  const out: SbomComponent[] = [];
  const re = /^\s*([A-Za-z0-9._-]+)\s*=\s*(?:["']([^"']+)["']|\{[^}]*version\s*=\s*["']([^"']+)["'])/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content))) {
    if (["name", "version", "edition", "authors", "license"].includes(m[1]!.toLowerCase())) continue;
    out.push(comp(m[1]!, m[2] ?? m[3] ?? "*", "crates.io", "runtime"));
  }
  return dedupe(out);
}

function parsePom(content: string): SbomComponent[] {
  const out: SbomComponent[] = [];
  const re = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)))
    out.push(comp(`${m[1]!.trim()}:${m[2]!.trim()}`, m[3]?.trim() ?? "*", "Maven", "runtime"));
  return dedupe(out);
}

function parseComposer(content: string): SbomComponent[] {
  try {
    const json = JSON.parse(content) as {
      require?: Record<string, string>;
      "require-dev"?: Record<string, string>;
    };
    const out: SbomComponent[] = [];
    for (const [n, v] of Object.entries(json.require ?? {}))
      if (n !== "php") out.push(comp(n, v, "Packagist", "runtime"));
    for (const [n, v] of Object.entries(json["require-dev"] ?? {}))
      out.push(comp(n, v, "Packagist", "development"));
    return dedupe(out);
  } catch {
    return [];
  }
}

function dedupe(list: SbomComponent[]): SbomComponent[] {
  const map = new Map<string, SbomComponent>();
  for (const c of list) {
    const key = `${c.ecosystem}|${c.name}`;
    const existing = map.get(key);
    if (!existing || (!existing.direct && c.direct)) map.set(key, c);
  }
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function severityFromCvss(score: number | null): DepVulnerability["severity"] {
  if (score === null) return "medium";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

export interface KevSignal {
  inKev: boolean;
  ransomware: boolean;
}

/**
 * Explainable priority score (0-100). Every contribution is returned so the UI
 * can show exactly why a package ranks where it does.
 */
export function prioritize(
  component: SbomComponent,
  vulns: DepVulnerability[],
  kev: KevSignal,
  epss: { score: number | null; percentile: number | null },
): CorrelatedComponent {
  const factors: CorrelatedComponent["priorityFactors"] = [];
  const maxCvss = vulns.reduce<number | null>(
    (acc, v) => (v.cvss === null ? acc : acc === null ? v.cvss : Math.max(acc, v.cvss)),
    null,
  );

  let score = 0;
  if (maxCvss !== null) {
    const c = Math.round(maxCvss * 4);
    score += c;
    factors.push({ factor: "Severity (CVSS)", contribution: c, detail: `Highest CVSS ${maxCvss.toFixed(1)}` });
  }
  if (kev.inKev) {
    score += 30;
    factors.push({ factor: "CISA KEV", contribution: 30, detail: "Confirmed exploitation in the wild" });
  }
  if (kev.ransomware) {
    score += 10;
    factors.push({ factor: "Ransomware campaign", contribution: 10, detail: "Used in known ransomware activity" });
  }
  if (epss.score !== null) {
    const c = Math.round(epss.score * 20);
    score += c;
    factors.push({
      factor: "EPSS",
      contribution: c,
      detail: `${(epss.score * 100).toFixed(1)}% chance of exploitation in 30 days`,
    });
  }
  if (component.scope === "runtime") {
    score += 8;
    factors.push({ factor: "Runtime reachability", contribution: 8, detail: "Ships in production dependency tree" });
  } else {
    factors.push({ factor: "Dev-only dependency", contribution: -6, detail: "Not deployed to production" });
    score -= 6;
  }
  if (component.direct) {
    score += 5;
    factors.push({ factor: "Direct dependency", contribution: 5, detail: "Declared by your project — easy to upgrade" });
  }
  const fixable = vulns.find((v) => v.fixedVersion);
  if (fixable) {
    score += 4;
    factors.push({ factor: "Fix available", contribution: 4, detail: `Patched in ${fixable.fixedVersion}` });
  }
  if (vulns.length > 1) {
    const c = Math.min(10, vulns.length);
    score += c;
    factors.push({ factor: "Multiple advisories", contribution: c, detail: `${vulns.length} known advisories` });
  }

  return {
    ...component,
    vulnerabilities: vulns.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0)),
    inKev: kev.inKev,
    kevRansomware: kev.ransomware,
    epss: epss.score,
    epssPercentile: epss.percentile,
    maxCvss,
    priority: Math.max(0, Math.min(100, score)),
    priorityFactors: factors,
    recommendedVersion: fixable?.fixedVersion ?? null,
  };
}

/** CycloneDX 1.5 JSON export. */
export function toCycloneDx(name: string, components: SbomComponent[], vulnsByPurl: Record<string, DepVulnerability[]>) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "AegisCode", name: "AegisCode SCA Engine", version: "1.0.0" }],
      component: { type: "application", name },
    },
    components: components.map((c) => ({
      type: "library",
      "bom-ref": c.purl,
      name: c.name,
      version: c.version,
      purl: c.purl,
      scope: c.scope === "development" ? "excluded" : "required",
    })),
    vulnerabilities: Object.entries(vulnsByPurl).flatMap(([ref, vulns]) =>
      vulns.map((v) => ({
        "bom-ref": `${ref}#${v.id}`,
        id: v.id,
        source: { name: "OSV", url: v.reference ?? "https://osv.dev" },
        ratings: v.cvss === null ? [] : [{ score: v.cvss, severity: v.severity, method: "CVSSv3" }],
        description: v.summary,
        affects: [{ ref }],
      })),
    ),
  };
}

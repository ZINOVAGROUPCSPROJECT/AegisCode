/**
 * Deterministic exploitability & attack-path correlation.
 *
 * Builds a graph from what the platform already knows — internet-facing
 * endpoints, code findings, vulnerable dependencies and sensitive assets — and
 * derives paths by joining nodes on concrete relationships (same file, same
 * route, same package, same data store). Nothing is attacked or probed here.
 */

export type NodeKind = "attacker" | "endpoint" | "vulnerability" | "dependency" | "component" | "asset";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  detail?: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
}

export interface GraphEdge {
  from: string;
  to: string;
  label: string;
}

export interface AttackPath {
  id: string;
  title: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** 0-100 — how dangerous this chain is, with the reasoning behind it. */
  danger: number;
  factors: { factor: string; contribution: number; detail: string }[];
  exploitability: "proven" | "likely" | "unlikely" | "theoretical";
  blastRadius: string;
  chokePoint: string;
  narrative: string;
}

export interface CorrelationInput {
  endpoints: {
    id: string;
    method: string;
    path: string;
    exposure: string;
    auth_required: boolean;
    handler?: string | null;
    risk_level?: string | null;
  }[];
  findings: {
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    cwe?: string | null;
    location?: string | null;
    exploitability?: string | null;
    in_kev?: boolean | null;
    cvss_score?: number | null;
    description?: string | null;
  }[];
  dependencies: {
    id: string;
    name: string;
    version?: string | null;
    severity?: string | null;
    cve?: string | null;
    in_kev?: boolean | null;
    reachable?: boolean | null;
  }[];
  assets: { id: string; label: string; sensitivity: "critical" | "high" | "medium" | "low" }[];
}

const SENSITIVE_HINTS: { re: RegExp; label: string; sensitivity: "critical" | "high" | "medium" }[] = [
  { re: /(user|account|profile|customer)/i, label: "User records (PII)", sensitivity: "high" },
  { re: /(payment|billing|card|invoice|stripe)/i, label: "Payment data", sensitivity: "critical" },
  { re: /(auth|session|token|password|credential|secret)/i, label: "Authentication material", sensitivity: "critical" },
  { re: /(admin|internal|ops|config)/i, label: "Administrative control plane", sensitivity: "critical" },
  { re: /(file|upload|storage|s3|bucket)/i, label: "Object storage", sensitivity: "high" },
  { re: /(db|database|sql|query|table)/i, label: "Primary database", sensitivity: "critical" },
];

const SINK_TO_IMPACT: Record<string, { impact: string; danger: number }> = {
  "CWE-89": { impact: "database read/write as the application role", danger: 30 },
  "CWE-78": { impact: "command execution on the application host", danger: 35 },
  "CWE-95": { impact: "arbitrary code execution in the app process", danger: 35 },
  "CWE-502": { impact: "arbitrary code execution via object graph", danger: 33 },
  "CWE-918": { impact: "access to internal-only services and metadata", danger: 25 },
  "CWE-22": { impact: "arbitrary file read on the host", danger: 25 },
  "CWE-639": { impact: "cross-tenant data access", danger: 25 },
  "CWE-862": { impact: "unauthenticated privileged actions", danger: 30 },
  "CWE-798": { impact: "direct credential reuse against dependent systems", danger: 32 },
  "CWE-347": { impact: "identity forgery for any user", danger: 34 },
  "CWE-79": { impact: "session hijack of authenticated users", danger: 18 },
  "CWE-601": { impact: "credential phishing via trusted domain", danger: 12 },
};

function sensitiveAssetFor(text: string): { label: string; sensitivity: "critical" | "high" | "medium" } {
  for (const hint of SENSITIVE_HINTS) if (hint.re.test(text)) return hint;
  return { label: "Application data store", sensitivity: "medium" };
}

/** File/route affinity: does a finding plausibly sit behind this endpoint? */
function linked(endpointPath: string, handler: string | null | undefined, location: string | null | undefined): boolean {
  if (!location) return false;
  const loc = location.toLowerCase();
  if (handler && loc.includes(handler.toLowerCase().split(/[.(\s]/)[0] ?? "")) return true;
  const segments = endpointPath
    .toLowerCase()
    .split("/")
    .filter((s) => s && !s.startsWith(":") && !s.startsWith("{") && s !== "api" && s.length > 2);
  return segments.some((s) => loc.includes(s));
}

export function correlateAttackPaths(input: CorrelationInput): AttackPath[] {
  const paths: AttackPath[] = [];
  const attacker: GraphNode = {
    id: "attacker",
    kind: "attacker",
    label: "Unauthenticated internet attacker",
    detail: "External, no credentials",
  };

  // ---- Paths seeded from exposed endpoints ----
  for (const ep of input.endpoints) {
    const exposed = /public|internet|external|unknown/i.test(ep.exposure);
    const related = input.findings.filter((f) => linked(ep.path, ep.handler, f.location));
    if (!exposed && related.length === 0) continue;
    const seeds = related.length > 0 ? related : [];
    for (const f of seeds) {
      const cwe = (f.cwe ?? "").toUpperCase();
      const sink = SINK_TO_IMPACT[cwe];
      const asset = sensitiveAssetFor(`${ep.path} ${f.title} ${f.description ?? ""}`);
      const factors: AttackPath["factors"] = [];
      let danger = 0;

      const sevWeight = { critical: 30, high: 24, medium: 14, low: 6, info: 2 }[f.severity];
      danger += sevWeight;
      factors.push({ factor: "Finding severity", contribution: sevWeight, detail: `${f.severity} severity finding` });

      if (exposed) {
        danger += 20;
        factors.push({ factor: "Internet exposure", contribution: 20, detail: `${ep.method} ${ep.path} is reachable externally` });
      }
      if (!ep.auth_required) {
        danger += 15;
        factors.push({ factor: "No authentication", contribution: 15, detail: "Endpoint requires no credentials" });
      }
      if (sink) {
        danger += sink.danger;
        factors.push({ factor: "Dangerous sink", contribution: sink.danger, detail: `${cwe} enables ${sink.impact}` });
      }
      if (f.in_kev) {
        danger += 15;
        factors.push({ factor: "Known exploited", contribution: 15, detail: "Matching CVE is in CISA KEV" });
      }
      if (asset.sensitivity === "critical") {
        danger += 12;
        factors.push({ factor: "Asset sensitivity", contribution: 12, detail: asset.label });
      }

      const nodes: GraphNode[] = [
        attacker,
        { id: `ep-${ep.id}`, kind: "endpoint", label: `${ep.method} ${ep.path}`, detail: ep.exposure },
        {
          id: `vuln-${f.id}`,
          kind: "vulnerability",
          label: f.title,
          detail: `${cwe || "no CWE"} · ${f.location ?? "unknown location"}`,
          severity: f.severity,
        },
        { id: `comp-${ep.id}`, kind: "component", label: ep.handler || "Request handler", detail: "Application code" },
        { id: `asset-${asset.label}`, kind: "asset", label: asset.label, detail: `${asset.sensitivity} sensitivity` },
      ];
      const edges: GraphEdge[] = [
        { from: "attacker", to: `ep-${ep.id}`, label: ep.auth_required ? "authenticated request" : "unauthenticated request" },
        { from: `ep-${ep.id}`, to: `comp-${ep.id}`, label: "routes to" },
        { from: `comp-${ep.id}`, to: `vuln-${f.id}`, label: "contains" },
        { from: `vuln-${f.id}`, to: `asset-${asset.label}`, label: sink ? sink.impact : "impacts" },
      ];

      paths.push({
        id: `path-ep-${ep.id}-${f.id}`,
        title: `${ep.method} ${ep.path} → ${f.title}`,
        nodes,
        edges,
        danger: Math.min(100, danger),
        factors,
        exploitability: classify(danger, f.exploitability ?? null),
        blastRadius: asset.label,
        chokePoint: ep.auth_required
          ? `Input validation in ${ep.handler || ep.path}`
          : `Authentication/authorization on ${ep.method} ${ep.path}`,
        narrative: `An attacker sends a crafted ${ep.method} request to ${ep.path}${
          ep.auth_required ? " using any valid account" : " with no credentials"
        }. The request reaches ${ep.handler || "the handler"}, where ${f.title.toLowerCase()} (${cwe || "unclassified"}) is present at ${
          f.location ?? "an unhardened code path"
        }. Successful exploitation yields ${sink ? sink.impact : "unauthorized access to application data"}, reaching ${asset.label}.`,
      });
    }
  }

  // ---- Paths seeded from vulnerable dependencies ----
  for (const dep of input.dependencies) {
    if (!dep.cve && !dep.severity) continue;
    const reachable = dep.reachable !== false;
    const factors: AttackPath["factors"] = [];
    let danger = 0;
    const sevWeight =
      { critical: 30, high: 24, medium: 14, low: 6 }[(dep.severity ?? "medium").toLowerCase() as "critical"] ?? 10;
    danger += sevWeight;
    factors.push({ factor: "Advisory severity", contribution: sevWeight, detail: `${dep.severity ?? "unknown"} severity` });
    if (reachable) {
      danger += 20;
      factors.push({ factor: "Reachable code", contribution: 20, detail: "Vulnerable function is called by the app" });
    }
    if (dep.in_kev) {
      danger += 20;
      factors.push({ factor: "Known exploited", contribution: 20, detail: `${dep.cve} is in CISA KEV` });
    }
    const entry = input.endpoints.find((e) => /public|internet|external/i.test(e.exposure)) ?? input.endpoints[0];
    if (entry) {
      danger += 10;
      factors.push({ factor: "Exposed entry point", contribution: 10, detail: `${entry.method} ${entry.path}` });
    }
    const asset = sensitiveAssetFor(dep.name);
    const nodes: GraphNode[] = [
      attacker,
      ...(entry
        ? [{ id: `ep-${entry.id}`, kind: "endpoint" as NodeKind, label: `${entry.method} ${entry.path}`, detail: entry.exposure }]
        : []),
      {
        id: `dep-${dep.id}`,
        kind: "dependency",
        label: `${dep.name}@${dep.version ?? "?"}`,
        detail: dep.cve ?? "advisory",
        severity: (dep.severity as GraphNode["severity"]) ?? "medium",
      },
      { id: `asset-dep-${dep.id}`, kind: "asset", label: asset.label, detail: `${asset.sensitivity} sensitivity` },
    ];
    const edges: GraphEdge[] = [
      ...(entry
        ? [
            { from: "attacker", to: `ep-${entry.id}`, label: "request" },
            { from: `ep-${entry.id}`, to: `dep-${dep.id}`, label: "data flows into library" },
          ]
        : [{ from: "attacker", to: `dep-${dep.id}`, label: "supplies crafted input" }]),
      { from: `dep-${dep.id}`, to: `asset-dep-${dep.id}`, label: "compromises" },
    ];
    paths.push({
      id: `path-dep-${dep.id}`,
      title: `${dep.name} ${dep.cve ?? "advisory"} → ${asset.label}`,
      nodes,
      edges,
      danger: Math.min(100, danger),
      factors,
      exploitability: classify(danger, dep.in_kev ? "proven" : null),
      blastRadius: asset.label,
      chokePoint: `Upgrade ${dep.name} or gate the input that reaches it`,
      narrative: `Attacker-controlled input entering ${
        entry ? `${entry.method} ${entry.path}` : "the application"
      } is processed by ${dep.name}@${dep.version ?? "?"}, which carries ${
        dep.cve ?? "a known advisory"
      }.${reachable ? " The vulnerable code path is reachable from application code." : " Reachability is unconfirmed."} Exploitation impacts ${asset.label}.`,
    });
  }

  return paths.sort((a, b) => b.danger - a.danger);
}

function classify(danger: number, hint: string | null): AttackPath["exploitability"] {
  if (hint === "proven") return "proven";
  if (danger >= 75) return "likely";
  if (danger >= 45) return "unlikely";
  return "theoretical";
}

export function dangerLabel(danger: number): "critical" | "high" | "medium" | "low" {
  if (danger >= 80) return "critical";
  if (danger >= 60) return "high";
  if (danger >= 35) return "medium";
  return "low";
}

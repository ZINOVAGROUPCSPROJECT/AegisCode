import { aegisAI } from "./ai.functions";
import type {
  AICodeAnalysisResult,
  AIExploitabilityResult,
  AIAttackPathsResult,
  AISupplyChainResult,
  AIBinaryResult,
  AIThreatIntelResult,
  AIRemediationResult,
  AIVerificationResult,
  AIDriftResult,
  AIInvestigationResult,
  AIApiSecurityResult,
  AIDastResult,
  AISecretScanResult,
  AIPrGateResult,
} from "./types";

import type { AegisActionName } from "./ai.contract";
import type { AttackPath, AttackPathStep } from "./types";

/** Hard caps keep Attack-Path requests fast and token-efficient. */
export const MAX_ATTACK_PATH_FINDINGS = 50;
export const MAX_ATTACK_PATH_CONTEXT = 8000;

export class AIRequestError extends Error {
  readonly status: number;
  readonly retryable: boolean;
  constructor(message: string, status: number, retryable: boolean) {
    super(message);
    this.name = "AIRequestError";
    this.status = status;
    this.retryable = retryable;
  }
}

async function callAI<T>(payload: {
  action: AegisActionName;
  userContent?: string;
  messages?: { role: "user" | "assistant"; content: string }[];
}): Promise<T> {
  let data: Awaited<ReturnType<typeof aegisAI>>;
  try {
    data = await aegisAI({ data: payload });
  } catch (error) {
    // Transport-level failures (offline, expired session, HTML error page from
    // a proxy) must never surface as a raw JSON parse error.
    const message = error instanceof Error ? error.message : String(error);
    throw new AIRequestError(
      /Unexpected token|JSON/i.test(message)
        ? "The server returned an unexpected response. Please sign in again and retry."
        : message || "The AI request could not be sent.",
      0,
      true,
    );
  }

  if (!data.ok) {
    throw new AIRequestError(data.error, data.status, data.retryable);
  }
  return data.result as T;
}

/**
 * The model is instructed to always return a summary block, but a truncated or
 * partial response must not crash the results view — rebuild it from findings.
 */
function normalizeAnalysis(
  result: AICodeAnalysisResult,
  code: string,
  language?: string,
): AICodeAnalysisResult {
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const count = (severity: string) => findings.filter((f) => f.severity === severity).length;
  const fallback = {
    total: findings.length,
    critical: count("critical"),
    high: count("high"),
    medium: count("medium"),
    low: count("low"),
    info: count("info"),
    language: language || "auto-detect",
    loc: code.split("\n").length,
  };
  const summary = { ...fallback, ...(result?.summary ?? {}) };
  return { ...result, findings, summary } as AICodeAnalysisResult;
}

/**
 * Only the fields the attack-path engine can actually reason about are sent —
 * full finding rows carry large evidence blobs that waste tokens.
 */
function slimFinding(finding: Record<string, unknown>): Record<string, unknown> {
  const pick = [
    "id",
    "title",
    "severity",
    "cwe",
    "cvss_score",
    "epss_score",
    "in_kev",
    "file_path",
    "line_start",
    "location",
    "reachability",
    "exploitability",
    "exploit_confidence",
    "status",
  ] as const;
  const out: Record<string, unknown> = {};
  for (const key of pick) {
    const value = finding[key];
    if (value !== null && value !== undefined && value !== "") out[key] = value;
  }
  const description = finding["description"];
  if (typeof description === "string" && description.trim()) {
    out["description"] = description.slice(0, 400);
  }
  return out;
}
const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 100,
  high: 78,
  medium: 52,
  low: 28,
  info: 10,
};

function clampScore(value: unknown, fallback: number): number {
  const num = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(0, Math.min(100, Math.round(num)));
}

function normalizeStep(step: unknown, index: number): AttackPathStep {
  if (typeof step === "string") {
    return { order: index + 1, action: step, node: "" };
  }
  const raw = (step ?? {}) as Record<string, unknown>;
  const mitreRaw = raw["mitre"] as Record<string, unknown> | undefined;
  const normalized: AttackPathStep = {
    order: typeof raw["order"] === "number" ? (raw["order"] as number) : index + 1,
    action: typeof raw["action"] === "string" ? (raw["action"] as string) : "",
    node: typeof raw["node"] === "string" ? (raw["node"] as string) : "",
  };
  if (typeof raw["node_type"] === "string") normalized.node_type = raw["node_type"] as string;
  if (typeof raw["classification"] === "string") {
    normalized.classification = raw["classification"] as NonNullable<AttackPathStep["classification"]>;
  }
  if (typeof raw["evidence"] === "string") normalized.evidence = raw["evidence"] as string;
  if (mitreRaw && typeof mitreRaw === "object" && typeof mitreRaw["id"] === "string") {
    normalized.mitre = {
      id: mitreRaw["id"] as string,
      ...(typeof mitreRaw["name"] === "string" ? { name: mitreRaw["name"] as string } : {}),
      ...(typeof mitreRaw["tactic"] === "string" ? { tactic: mitreRaw["tactic"] as string } : {}),
    };
  }
  return normalized;
}

/** Risk = realistic exploit likelihood x impact, not raw severity alone. */
function deriveRiskScore(path: AttackPath): number {
  if (typeof path.risk_score === "number" && Number.isFinite(path.risk_score)) {
    return clampScore(path.risk_score, 0);
  }
  const factors = path.risk_factors ?? {};
  const parts = [factors.severity, factors.exploitability, factors.exposure, factors.impact]
    .filter((v): v is number => typeof v === "number" && Number.isFinite(v));
  const confidence = clampScore(path.confidence, 50) / 100;
  if (parts.length > 0) {
    const avg = parts.reduce((a, b) => a + b, 0) / parts.length;
    return clampScore(avg * (0.6 + 0.4 * confidence), 0);
  }
  const statusWeight =
    path.status === "validated" ? 100 : path.status === "reachable" ? 75 : 45;
  const impactWeight = SEVERITY_WEIGHT[String(path.impact ?? "").toLowerCase()] ?? 55;
  return clampScore(statusWeight * 0.6 + impactWeight * 0.4 * confidence, 0);
}

function normalizeAttackPaths(result: AIAttackPathsResult): AIAttackPathsResult {
  const rawPaths = Array.isArray(result?.paths) ? result.paths : [];
  const paths = rawPaths.map((raw, index) => {
    const path = { ...(raw as AttackPath) };
    path.id = typeof path.id === "string" && path.id ? path.id : `path-${index + 1}`;
    path.name = typeof path.name === "string" && path.name ? path.name : `Attack path ${index + 1}`;
    path.status = (["theoretical", "reachable", "validated"] as const).includes(
      path.status as never,
    )
      ? path.status
      : "theoretical";
    path.confidence = clampScore(path.confidence, 50);
    path.steps = (Array.isArray(raw.steps) ? raw.steps : []).map(normalizeStep);
    path.evidence = Array.isArray(path.evidence) ? path.evidence : [];
    path.remediation = Array.isArray(path.remediation)
      ? path.remediation.filter((r): r is string => typeof r === "string")
      : [];
    path.prerequisites = Array.isArray(path.prerequisites)
      ? path.prerequisites.filter((p): p is string => typeof p === "string")
      : [];
    path.finding_ids = Array.isArray(path.finding_ids)
      ? path.finding_ids.filter((f): f is string => typeof f === "string")
      : [];
    path.risk_score = deriveRiskScore(path);
    return path;
  });

  paths.sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0) || b.confidence - a.confidence);

  const graph = result?.graph ?? { nodes: [], edges: [] };
  return {
    ...result,
    paths,
    graph: {
      nodes: Array.isArray(graph.nodes) ? graph.nodes : [],
      edges: Array.isArray(graph.edges) ? graph.edges : [],
    },
  };
}

export const ai = {
  analyzeCode: async (code: string, language?: string) => {
    const result = await callAI<AICodeAnalysisResult>({
      action: "analyze_code",
      userContent: `Language: ${language || "auto-detect"}\n\nAnalyze the following code for security vulnerabilities:\n\n\`\`\`\n${code}\n\`\`\``,
    });
    return normalizeAnalysis(result, code, language);
  },

  assessExploitability: (finding: Record<string, unknown>, appContext: string) =>
    callAI<AIExploitabilityResult>({
      action: "exploitability",
      userContent: `Vulnerability finding:\n${JSON.stringify(finding, null, 2)}\n\nApplication context:\n${appContext}`,
    }),

  generateAttackPaths: async (findings: Record<string, unknown>[], appContext: string) => {
    const result = await callAI<AIAttackPathsResult>({
      action: "attack_paths",
      userContent: `Findings (${Math.min(findings.length, MAX_ATTACK_PATH_FINDINGS)} of ${findings.length}):\n${JSON.stringify(
        findings.slice(0, MAX_ATTACK_PATH_FINDINGS).map(slimFinding),
      )}\n\nApplication context:\n${String(appContext ?? "").slice(0, MAX_ATTACK_PATH_CONTEXT)}`,
    });
    return normalizeAttackPaths(result);
  },

  analyzeSupplyChain: (manifest: string, appContext: string) =>
    callAI<AISupplyChainResult>({
      action: "supply_chain",
      userContent: `Dependency manifest / SBOM input:\n${manifest}\n\nApplication context:\n${appContext}`,
    }),

  reverseEngineer: (binaryMetadata: string) =>
    callAI<AIBinaryResult>({
      action: "reverse_engineering",
      userContent: `Binary metadata (strings, imports, functions, behavior):\n${binaryMetadata}`,
    }),

  fuseThreatIntel: (cves: string[], context: string) =>
    callAI<AIThreatIntelResult>({
      action: "threat_intel",
      userContent: `CVEs to correlate: ${cves.join(", ") || "none provided"}\n\nContext:\n${context}`,
    }),

  remediate: (finding: Record<string, unknown>, code: string) =>
    callAI<AIRemediationResult>({
      action: "remediate",
      userContent: `Vulnerability:\n${JSON.stringify(finding, null, 2)}\n\nOriginal code:\n\`\`\`\n${code}\n\`\`\``,
    }),

  verifyRemediation: (finding: Record<string, unknown>, fixedCode: string) =>
    callAI<AIVerificationResult>({
      action: "verify_remediation",
      userContent: `Original vulnerability:\n${JSON.stringify(finding, null, 2)}\n\nRemediated code:\n\`\`\`\n${fixedCode}\n\`\`\``,
    }),

  detectDrift: (before: string, after: string) =>
    callAI<AIDriftResult>({
      action: "drift",
      userContent: `BEFORE state:\n${before}\n\nAFTER state:\n${after}`,
    }),

  investigate: (context: string) =>
    callAI<AIInvestigationResult>({
      action: "investigate",
      userContent: context,
    }),

  scanApis: (input: string, appContext: string) =>
    callAI<AIApiSecurityResult>({
      action: "api_security",
      userContent: `API surface (routes, OpenAPI spec, controller code or endpoint list):\n${input}\n\nApplication context:\n${appContext}`,
    }),

  runDast: (target: string, evidence: string) =>
    callAI<AIDastResult>({
      action: "dast",
      userContent: `Target: ${target}\n\nRuntime evidence (headers, responses, transcript, stack details):\n${evidence}`,
    }),

  detectSecrets: (content: string, source: string) =>
    callAI<AISecretScanResult>({
      action: "secret_detection",
      userContent: `Source: ${source}\n\nContent to scan for exposed credentials:\n${content}`,
    }),

  gatePullRequest: (
    pr: { title: string; author?: string; branch?: string; diff: string },
    policy: string,
  ) =>
    callAI<AIPrGateResult>({
      action: "pr_gate",
      userContent: `Pull request: ${pr.title}\nAuthor: ${pr.author || "unknown"}\nBranch: ${pr.branch || "unknown"}\n\nBlocking policy:\n${policy}\n\nDiff:\n${pr.diff}`,
    }),

  chat: (messages: { role: "user" | "assistant"; content: string }[]) =>
    callAI<string>({
      action: "chat",
      messages,
    }),
};

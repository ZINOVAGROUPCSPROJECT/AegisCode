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

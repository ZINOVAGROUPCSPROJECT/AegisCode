/**
 * AegisCode AI engine (server-only).
 *
 * Holds every system prompt and the single gateway call used by all analysis
 * actions. The prompts define the exact JSON contract each action returns.
 */

export type AegisAction =
  | "analyze_code"
  | "exploitability"
  | "attack_paths"
  | "supply_chain"
  | "reverse_engineering"
  | "threat_intel"
  | "remediate"
  | "verify_remediation"
  | "drift"
  | "investigate"
  | "api_security"
  | "dast"
  | "secret_detection"
  | "pr_gate"
  | "chat";

export type Role = "system" | "user" | "assistant";

export interface ChatMessage {
  role: Role;
  content: string;
}

export interface AegisRequest {
  action: AegisAction;
  messages?: ChatMessage[];
  systemPrompt?: string;
  userContent?: string;
  temperature?: number;
  maxTokens?: number;
}

/**
 * Default model served by the Lovable AI Gateway. The gateway keeps the
 * credential server-side; the browser never sees a provider key.
 */
export const AEGIS_MODEL = "openai/gpt-oss-20b:free";
export const AEGIS_FALLBACK_MODEL = "google/gemini-3.6-flash";

const LOVABLE_GATEWAY_URL = "https://ai.gateway.lovable.dev/v1/chat/completions";
const OPENROUTER_GATEWAY_URL = "https://openrouter.ai/api/v1/chat/completions";

export const SYSTEM_PROMPTS: Record<AegisAction, string> = {
  analyze_code: `You are AegisCode, an elite application security analyst. Analyze code for vulnerabilities with surgical precision.
For EVERY finding, you MUST return a JSON object with this exact shape:
{
  "summary": { "total": number, "critical": number, "high": number, "medium": number, "low": number, "info": number, "language": string, "loc": number },
  "findings": [
    {
      "title": string,
      "description": string,
      "severity": "critical"|"high"|"medium"|"low"|"info",
      "cwe": "CWE-XXX",
      "cwe_name": string,
      "cvss_score": number (0-10),
      "cvss_vector": string,
      "location": string,
      "file_path": string|null,
      "line_start": number|null,
      "line_end": number|null,
      "evidence": [{ "type": "code"|"config"|"behavior", "snippet": string, "explanation": string, "classification": "observed"|"verified"|"inferred"|"unknown" }],
      "evidence_chain": [{ "step": number, "node": string, "node_type": "cve"|"dependency"|"function"|"data_flow"|"endpoint"|"attack_path"|"impact", "detail": string, "classification": "observed"|"verified"|"inferred"|"unknown" }],
      "remediation": string,
      "secure_fix": string (code block with the corrected code),
      "reachability": "observed"|"verified"|"inferred"|"unknown",
      "exploitability": "exploitable"|"reachable"|"theoretical"|"not-exploitable"|"unknown",
      "exploit_confidence": number (0-100),
      "attack_paths": [{ "id": string, "name": string, "steps": [string], "status": "theoretical"|"reachable"|"validated", "confidence": number }],
      "data_flow": [{ "step": number, "point": string, "detail": string }],
      "verdict": { "exploitable_in_this_app": boolean, "confidence": number, "reasoning": string, "classification": "observed"|"verified"|"inferred"|"unknown" }
    }
  ]
}
RULES:
- Never fabricate evidence. Only cite code/config that is actually present in the input.
- Mark every piece of evidence with one of: observed / verified / inferred / unknown.
- Never claim 100% safety. If no vulnerabilities found, say so and note the analysis is not exhaustive.
- If you cannot determine something, use "unknown" — do not guess.
- Return ONLY the JSON, no markdown fences, no commentary.`,

  exploitability: `You are AegisCode's Application-Aware Exploitability Engine. Given a vulnerability finding and its application context, determine whether it is ACTUALLY reachable and exploitable in THIS application.
Return JSON:
{
  "exploitability": "exploitable"|"reachable"|"theoretical"|"not-exploitable"|"unknown",
  "confidence": number (0-100),
  "reasoning": string,
  "reachability_chain": [{ "step": number, "point": string, "reachable": boolean, "classification": "observed"|"verified"|"inferred"|"unknown" }],
  "conditions_required": [string],
  "attack_surface": string,
  "mitigations_present": [string],
  "verdict": string,
  "classification": "observed"|"verified"|"inferred"|"unknown"
}
Never claim 100% safety. Distinguish observed/verified/inferred/unknown. Return ONLY JSON.`,

  attack_paths: `You are AegisCode's Attack-Path Engine. Reconstruct and visualize attack paths from vulnerabilities and application context.
Return JSON:
{
  "paths": [
    {
      "id": string,
      "name": string,
      "status": "theoretical"|"reachable"|"validated",
      "confidence": number (0-100),
      "classification": "observed"|"verified"|"inferred"|"unknown",
      "entry_point": string,
      "steps": [{ "order": number, "action": string, "node": string, "node_type": string, "classification": "observed"|"verified"|"inferred"|"unknown" }],
      "impact": string,
      "prerequisites": [string]
    }
  ],
  "graph": { "nodes": [{ "id": string, "label": string, "type": string }], "edges": [{ "from": string, "to": string, "label": string }] }
}
Never invent nodes that are not supported by the input. Return ONLY JSON.`,

  supply_chain: `You are AegisCode's Supply-Chain Security analyzer. Analyze dependencies for risk, poisoning indicators, behavioral fingerprints, and blast radius.
Return JSON:
{
  "sbom": [{ "name": string, "version": string, "ecosystem": string, "license": string, "direct": boolean }],
  "dependencies": [
    {
      "name": string, "version": string, "ecosystem": string, "risk_level": "critical"|"high"|"medium"|"low"|"none"|"unknown",
      "vulnerabilities": [{ "cve": string, "severity": string, "fixed_in": string|null, "description": string }],
      "poisoning_indicators": [string],
      "behavioral_fingerprint": { "network": [string], "filesystem": [string], "process": [string], "crypto": [string] },
      "blast_radius": { "scope": string, "affected_components": [string], "data_exposure": string },
      "reachability": "observed"|"verified"|"inferred"|"unknown"
    }
  ],
  "summary": { "total": number, "critical": number, "high": number, "poisoning_risk": number }
}
Return ONLY JSON. Never fabricate CVEs — if unknown, mark unknown.`,

  reverse_engineering: `You are AegisCode's Reverse Engineering analyzer. Analyze binary metadata (strings, imports, functions, behavior) for security-relevant findings.
Return JSON:
{
  "summary": { "format": string, "architecture": string, "sha256": string, "risk_level": string },
  "strings": [{ "value": string, "category": "url"|"path"|"credential"|"ip"|"command"|"other", "risk": "high"|"medium"|"low" }],
  "imports": [{ "name": string, "library": string, "risk": "high"|"medium"|"low", "note": string }],
  "functions": [{ "name": string, "address": string, "risk": "high"|"medium"|"low" }],
  "suspicious_apis": [{ "api": string, "reason": string, "risk": string }],
  "behavior": { "network": [string], "filesystem": [string], "process": [string], "registry": [string], "crypto": [string] },
  "behavioral_diff": { "summary": string, "differences": [string] },
  "integrity_mismatches": [{ "type": "source-build"|"build-binary"|"binary-runtime", "description": string, "severity": string, "classification": "observed"|"verified"|"inferred"|"unknown" }]
}
Return ONLY JSON.`,

  threat_intel: `You are AegisCode's Threat Intelligence Fusion engine. Correlate CVE/NVD/OSV/CISA KEV/EPSS/vendor intelligence.
Return JSON:
{
  "records": [
    {
      "cve": string, "source": "nvd"|"osv"|"cisa-kev"|"epss"|"vendor"|"internal",
      "description": string, "cvss_score": number, "epss_score": number, "epss_percentile": number,
      "in_kev": boolean, "kev_date": string|null,
      "references": [{ "url": string, "source": string }],
      "classification": "observed"|"verified"|"inferred"|"unknown"
    }
  ],
  "fusion_summary": string
}
Return ONLY JSON. Mark inferred vs verified clearly. Never fabricate CVE IDs.`,

  remediate: `You are AegisCode's Remediation engine. Generate a secure fix for the given vulnerability and explain it.
Return JSON:
{
  "fix_description": string,
  "fix_code": string (the complete corrected code),
  "changes": [{ "file": string, "change": string, "reason": string }],
  "verification_steps": [string],
  "residual_risk": string
}
Return ONLY JSON.`,

  verify_remediation: `You are AegisCode's independent Verification engine. Given the original vulnerability and the remediated code, independently verify whether the vulnerability/attack path is gone.
Return JSON:
{
  "verification_status": "verified"|"failed"|"unknown",
  "original_issue": string,
  "checks": [{ "check": string, "passed": boolean, "detail": string, "classification": "observed"|"verified"|"inferred"|"unknown" }],
  "residual_issues": [string],
  "verdict": string,
  "confidence": number (0-100)
}
Never claim 100% safety. Return ONLY JSON.`,

  drift: `You are AegisCode's Security Drift detector. Compare before/after states to detect security-relevant drift.
Return JSON:
{
  "drift_records": [
    {
      "drift_type": "dependency"|"code"|"configuration"|"artifact"|"behavior",
      "description": string, "severity": "critical"|"high"|"medium"|"low"|"info",
      "security_impact": string, "classification": "observed"|"verified"|"inferred"|"unknown"
    }
  ],
  "summary": string
}
Return ONLY JSON.`,

  investigate: `You are AegisCode's AI Security Investigator. Investigate findings using code, dependencies, configuration, evidence, and threat intelligence. Provide a thorough investigation report.
Return JSON:
{
  "investigation_summary": string,
  "hypotheses": [{ "hypothesis": string, "supported_by": [string], "contradicted_by": [string], "confidence": number, "classification": "observed"|"verified"|"inferred"|"unknown" }],
  "correlations": [{ "finding": string, "correlated_with": string, "relationship": string, "strength": "strong"|"moderate"|"weak" }],
  "recommendations": [string],
  "open_questions": [string]
}
Return ONLY JSON.`,

  api_security: `You are AegisCode's API Security Engine. Discover every API endpoint in the supplied code, specification or route list, then test each one on paper for broken authentication, broken object-level authorization (IDOR), injection, SSRF, mass assignment, rate-limit abuse and excessive data exposure.
Return ONLY JSON with this exact shape:
{
  "summary": { "total_endpoints": number, "unauthenticated": number, "high_risk": number, "tested": number, "failed_tests": number },
  "endpoints": [
    {
      "method": string,
      "path": string,
      "handler": string|null,
      "auth_required": boolean,
      "auth_mechanism": string|null,
      "exposure": "public"|"authenticated"|"internal"|"unknown",
      "parameters": [{ "name": string, "location": "path"|"query"|"body"|"header", "type": string, "user_controlled": boolean }],
      "risks": [{ "category": "broken_auth"|"idor"|"injection"|"ssrf"|"mass_assignment"|"rate_limit"|"data_exposure"|"other", "severity": "critical"|"high"|"medium"|"low"|"info", "detail": string, "classification": "observed"|"verified"|"inferred"|"unknown" }],
      "risk_level": "critical"|"high"|"medium"|"low"|"none"|"unknown",
      "notes": string|null,
      "tests": [{ "category": string, "name": string, "outcome": "vulnerable"|"safe"|"inconclusive"|"unknown", "severity": "critical"|"high"|"medium"|"low"|"info"|null, "request_example": string, "expected": string, "observed": string, "classification": "observed"|"verified"|"inferred"|"unknown", "remediation": string }]
    }
  ]
}
Only report endpoints you can actually see. Mark anything you cannot prove as "inferred" or "unknown". Never invent endpoints or test results.`,

  dast: `You are AegisCode's DAST / Runtime Testing Engine. Given a live target description (URL, stack, observed responses, headers, or a captured HTTP transcript), design and evaluate runtime probes that confirm or refute vulnerabilities.
Return ONLY JSON with this exact shape:
{
  "summary": { "target": string, "probes_run": number, "confirmed": number, "refuted": number, "inconclusive": number, "risk": "critical"|"high"|"medium"|"low"|"none"|"unknown" },
  "probes": [
    { "name": string, "category": string, "request": string, "expected_signal": string, "observed_signal": string, "verdict": "confirmed"|"refuted"|"inconclusive", "classification": "observed"|"verified"|"inferred"|"unknown" }
  ],
  "findings": [
    {
      "title": string,
      "severity": "critical"|"high"|"medium"|"low"|"info",
      "cwe": string|null,
      "confirmed_at_runtime": boolean,
      "confidence": number,
      "evidence": [{ "type": "request"|"response"|"timing"|"behavior", "snippet": string, "explanation": string, "classification": "observed"|"verified"|"inferred"|"unknown" }],
      "reproduction": string,
      "impact": string,
      "remediation": string
    }
  ],
  "runtime_notes": string
}
Only mark confirmed_at_runtime true when the supplied runtime evidence actually demonstrates it. Never fabricate HTTP responses.`,

  secret_detection: `You are AegisCode's Secret Detection Engine. Find exposed credentials, API keys, tokens, private keys, connection strings and passwords in the supplied content.
Return ONLY JSON with this exact shape:
{
  "summary": { "total": number, "critical": number, "high": number, "medium": number, "low": number, "verified_live": number },
  "secrets": [
    {
      "secret_type": string,
      "provider": string|null,
      "severity": "critical"|"high"|"medium"|"low"|"info",
      "masked_value": string,
      "location": string,
      "line_start": number|null,
      "entropy": number|null,
      "validity": "likely_live"|"likely_test"|"revoked"|"unknown",
      "classification": "observed"|"verified"|"inferred"|"unknown",
      "impact": string,
      "remediation": string,
      "rotation_steps": [string]
    }
  ]
}
CRITICAL: never echo a full secret. Always mask, keeping at most the first 4 and last 2 characters. Do not report obvious placeholders as live credentials.`,

  pr_gate: `You are AegisCode's CI/CD Pull-Request Gate. Review a pull request diff for newly introduced security risk and decide whether the deployment should be blocked according to the supplied policy.
Return ONLY JSON with this exact shape:
{
  "summary": { "files_changed": number, "introduced": number, "resolved": number, "risk": "critical"|"high"|"medium"|"low"|"none"|"unknown" },
  "gate_status": "passed"|"blocked"|"warning",
  "blocking_reasons": [string],
  "findings": [
    {
      "title": string,
      "severity": "critical"|"high"|"medium"|"low"|"info",
      "cwe": string|null,
      "file_path": string|null,
      "line_start": number|null,
      "status": "introduced"|"resolved"|"pre_existing",
      "exploitability": "exploitable"|"reachable"|"theoretical"|"not-exploitable"|"unknown",
      "evidence": [{ "type": string, "snippet": string, "explanation": string, "classification": "observed"|"verified"|"inferred"|"unknown" }],
      "remediation": string,
      "suggested_patch": string|null
    }
  ],
  "review_comment": string
}
Judge only the supplied diff. Apply the policy exactly: block when the policy threshold is met, otherwise pass or warn.`,

  chat: `You are AegisCode, an expert AI security assistant. Answer questions about application security, supply-chain security, reverse engineering, vulnerability analysis, and exploitability. Be precise and evidence-driven. Distinguish observed/verified/inferred/unknown. Never claim 100% safety. Never fabricate CVEs or evidence.`,
};

/** Strips markdown fences / prose and returns the first parsable JSON value. */
function repairTruncatedJson(text: string): unknown {
  const start = text.search(/[[{]/);
  if (start < 0) return null;
  const body = text.slice(start);

  const stack: string[] = [];
  let inString = false;
  let escaped = false;
  let lastSafe = -1;

  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") stack.push("}");
    else if (ch === "[") stack.push("]");
    else if (ch === "}" || ch === "]") stack.pop();
    // A complete element boundary is a safe place to cut a truncated document.
    if (!inString && (ch === "}" || ch === "]")) lastSafe = i;
  }

  if (lastSafe < 0) return null;

  const head = body.slice(0, lastSafe + 1);
  const openStack: string[] = [];
  inString = false;
  escaped = false;
  for (let i = 0; i < head.length; i += 1) {
    const ch = head[i]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") openStack.push("}");
    else if (ch === "[") openStack.push("]");
    else if (ch === "}" || ch === "]") openStack.pop();
  }

  const candidate = head + openStack.reverse().join("");
  try {
    return JSON.parse(candidate);
  } catch {
    return null;
  }
}

function extractJson(content: string): unknown {
  const trimmed = content.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // fall through
  }

  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced?.[1]) {
    try {
      return JSON.parse(fenced[1].trim());
    } catch {
      // fall through
    }
  }

  // Truncated documents: close whatever structures remain open so a partial
  // (but valid) analysis is still usable instead of being discarded.
  const repaired = repairTruncatedJson(trimmed);
  if (repaired) return repaired;

  const firstBrace = trimmed.search(/[[{]/);
  const lastBrace = Math.max(trimmed.lastIndexOf("}"), trimmed.lastIndexOf("]"));
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    try {
      return JSON.parse(trimmed.slice(firstBrace, lastBrace + 1));
    } catch {
      // fall through
    }
  }

  return content;
}

export interface AegisEnvelope {
  ok: true;
  action: AegisAction;
  model: string;
  result: unknown;
  usage: unknown;
}

interface GatewayTarget {
  url: string;
  headers: Record<string, string>;
  model: string;
  name: string;
}

/**
 * Resolve the provider chain. The managed Lovable AI Gateway is primary: its
 * key is injected server-side, which removes the 401s caused by a missing or
 * browser-exposed provider key. An OpenRouter key, when present, is used as a
 * fallback so self-hosted deployments keep working.
 */
function resolveGatewayTargets(): GatewayTarget[] {
  const targets: GatewayTarget[] = [];
  const lovableKey = process.env["LOVABLE_API_KEY"];
  const openRouterKey = process.env["OPENROUTER_API_KEY"];

  if (lovableKey) {
    targets.push({
      name: "lovable",
      url: LOVABLE_GATEWAY_URL,
      model: AEGIS_MODEL,
      headers: {
        "Lovable-API-Key": lovableKey,
        "Content-Type": "application/json",
      },
    });
  }

  if (openRouterKey) {
    targets.push({
      name: "openrouter",
      url: OPENROUTER_GATEWAY_URL,
      model: AEGIS_FALLBACK_MODEL,
      headers: {
        Authorization: `Bearer ${openRouterKey}`,
        "Content-Type": "application/json",
      },
    });
  }

  return targets;
}

export class AegisAIError extends Error {
  readonly status: number;
  readonly retryable: boolean;

  constructor(message: string, status = 502, retryable = false) {
    super(message);
    this.name = "AegisAIError";
    this.status = status;
    this.retryable = retryable;
  }
}

function describeGatewayFailure(status: number, bodyText: string): AegisAIError {
  const detail = bodyText.replace(/\s+/g, " ").slice(0, 300);
  if (status === 401 || status === 403) {
    return new AegisAIError(
      "AegisCode is not authorised to reach the AI gateway. The server-side AI key is missing, expired or revoked.",
      status,
    );
  }
  if (status === 402) {
    return new AegisAIError("AI credits are exhausted for this workspace.", 402);
  }
  if (status === 429) {
    return new AegisAIError("AI rate limit reached. Please wait a moment and try again.", 429, true);
  }
  if (status >= 500) {
    return new AegisAIError(`The AI provider is temporarily unavailable (${status}).`, status, true);
  }
  return new AegisAIError(`AI gateway error (${status}): ${detail}`, status);
}

/**
 * Gateways and proxies can answer with an HTML error page instead of JSON.
 * Parsing that blindly is what produced "Unexpected token '<'" in the UI, so
 * the body is inspected before it is parsed.
 */
async function readJsonResponse(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json") && !text.trimStart().startsWith("{")) {
    throw new AegisAIError(
      "The AI gateway returned a non-JSON response. This usually means the request was intercepted by a proxy or the service is down.",
      502,
      true,
    );
  }
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new AegisAIError("The AI gateway returned an unreadable response.", 502, true);
  }
}

export async function runAegisAI(body: AegisRequest): Promise<AegisEnvelope> {
  const targets = resolveGatewayTargets();
  if (targets.length === 0) {
    throw new AegisAIError(
      "AI is not configured on this server. Set LOVABLE_API_KEY (or OPENROUTER_API_KEY) in the server environment.",
      500,
    );
  }

  if (!body.action || !SYSTEM_PROMPTS[body.action]) {
    throw new Error(
      `Invalid or missing action. Must be one of: ${Object.keys(SYSTEM_PROMPTS).join(", ")}`,
    );
  }

  const systemPrompt = body.systemPrompt || SYSTEM_PROMPTS[body.action];

  let messages: ChatMessage[];
  if (body.messages && body.messages.length > 0) {
    messages = [{ role: "system", content: systemPrompt }, ...body.messages];
  } else if (body.userContent) {
    messages = [
      { role: "system", content: systemPrompt },
      { role: "user", content: body.userContent },
    ];
  } else {
    throw new Error("Either 'messages' or 'userContent' must be provided.");
  }

  let lastError: AegisAIError | undefined;
  let data:
    | {
        model?: string;
        usage?: unknown;
        choices?: { message?: { content?: string }; finish_reason?: string }[];
      }
    | undefined;
  let usedModel = AEGIS_MODEL;

  for (const target of targets) {
    let response: Response;
    try {
      response = await fetch(target.url, {
        method: "POST",
        headers: target.headers,
        body: JSON.stringify({
          model: target.model,
          messages,
          temperature: body.temperature ?? 0.2,
          max_tokens: body.maxTokens ?? 32000,
          // Every action except free-form chat must return a strict JSON document.
          ...(body.action === "chat" ? {} : { response_format: { type: "json_object" } }),
        }),
      });
    } catch (networkError) {
      lastError = new AegisAIError(
        `Could not reach the AI provider (${target.name}): ${(networkError as Error).message}`,
        503,
        true,
      );
      continue;
    }

    if (!response.ok) {
      lastError = describeGatewayFailure(response.status, await response.text());
      // Auth/config failures on one provider are worth retrying on the next.
      if (
  lastError.status === 401 ||
  lastError.status === 403 ||
  lastError.status === 402 ||
  lastError.status === 429 ||
  lastError.status >= 500
) {
  continue;
}

throw lastError;
      continue;
    }

    data = (await readJsonResponse(response)) as typeof data;
    usedModel = target.model;
    break;
  }

  if (!data) {
    throw lastError ?? new AegisAIError("The AI request failed.", 502, true);
  }

  const choice = data.choices?.[0];
  const content = choice?.message?.content;
  if (!content) {
    throw new AegisAIError("The AI returned an empty response.", 502, true);
  }

  if (body.action === "chat") {
    return {
      ok: true,
      action: body.action,
      model: data.model || usedModel,
      result: content,
      usage: data.usage ?? null,
    };
  }

  const parsed = extractJson(content);
  // A truncated document parses as a bare string; surfacing it as an empty
  // result would silently report "no vulnerabilities" for risky code.
  if (typeof parsed === "string") {
    if (choice?.finish_reason === "length") {
      throw new AegisAIError(
        "The analysis was too large for a single response. Try analyzing a smaller portion of the input.",
        413,
      );
    }
    throw new AegisAIError(
      "The AI returned a malformed response. Please run the analysis again.",
      502,
      true,
    );
  }

  return {
    ok: true,
    action: body.action,
    model: data.model || usedModel,
    result: parsed,
    usage: data.usage ?? null,
  };
}

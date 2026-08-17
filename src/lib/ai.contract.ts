/**
 * Shared, browser-safe AI contract.
 *
 * Both the client helpers and the server function validate against these
 * values, so an unknown action or an oversized payload is rejected before it
 * ever reaches a provider.
 */
export const AEGIS_ACTIONS = [
  "analyze_code",
  "exploitability",
  "attack_paths",
  "supply_chain",
  "reverse_engineering",
  "threat_intel",
  "remediate",
  "verify_remediation",
  "drift",
  "investigate",
  "api_security",
  "dast",
  "secret_detection",
  "pr_gate",
  "chat",
] as const;

export type AegisActionName = (typeof AEGIS_ACTIONS)[number];

/** Roughly 200k characters — large enough for a file, small enough to bound cost. */
export const MAX_AI_INPUT_CHARS = 200_000;

/** Conversation window sent to the model. */
export const MAX_AI_MESSAGES = 40;

export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

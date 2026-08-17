import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type {
  Severity,
  Classification,
  Exploitability,
  RiskLevel,
  AttackPathStatus,
} from "./types";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export function classNames(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

export function severityColor(s: Severity): string {
  switch (s) {
    case "critical":
      return "text-danger bg-danger/15 border-danger/30";
    case "high":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "medium":
      return "text-warning bg-warning/15 border-warning/30";
    case "low":
      return "text-cyber-300 bg-cyber-500/10 border-cyber-500/25";
    case "info":
      return "text-ink-300 bg-ink-700/40 border-ink-600/40";
  }
}

export function severityRank(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] ?? 0;
}

export function severityLabel(s: Severity): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function classificationColor(c: Classification): string {
  switch (c) {
    case "observed":
      return "text-cyber-300 bg-cyber-500/10 border-cyber-500/25";
    case "verified":
      return "text-volt-300 bg-volt-500/10 border-volt-500/25";
    case "inferred":
      return "text-warning bg-warning/10 border-warning/20";
    case "unknown":
      return "text-ink-400 bg-ink-700/40 border-ink-600/40";
  }
}

export function classificationLabel(c: Classification): string {
  return c.charAt(0).toUpperCase() + c.slice(1);
}

export function exploitabilityColor(e: Exploitability): string {
  switch (e) {
    case "exploitable":
      return "text-danger bg-danger/15 border-danger/30";
    case "reachable":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "theoretical":
      return "text-warning bg-warning/15 border-warning/30";
    case "not-exploitable":
      return "text-volt-300 bg-volt-500/10 border-volt-500/25";
    case "unknown":
      return "text-ink-400 bg-ink-700/40 border-ink-600/40";
  }
}

export function exploitabilityLabel(e: Exploitability): string {
  return e
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function riskColor(r: RiskLevel): string {
  switch (r) {
    case "critical":
      return "text-danger bg-danger/15 border-danger/30";
    case "high":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "medium":
      return "text-warning bg-warning/15 border-warning/30";
    case "low":
      return "text-cyber-300 bg-cyber-500/10 border-cyber-500/25";
    case "none":
      return "text-volt-300 bg-volt-500/10 border-volt-500/25";
    case "unknown":
      return "text-ink-400 bg-ink-700/40 border-ink-600/40";
  }
}

export function attackPathStatusColor(s: AttackPathStatus): string {
  switch (s) {
    case "validated":
      return "text-danger bg-danger/15 border-danger/30";
    case "reachable":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "theoretical":
      return "text-warning bg-warning/15 border-warning/30";
  }
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(iso);
}

export async function sha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

export function countLines(code: string): number {
  return code.split("\n").length;
}

export function downloadFile(filename: string, content: string, type = "application/json"): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

/* ============================================================
 * Aegis Risk Score
 *
 * One priority number per finding, combining base severity,
 * proven exploitability, exposure, asset importance and live
 * threat intelligence (KEV / EPSS). Deterministic on purpose:
 * the same inputs must always produce the same priority.
 * ============================================================ */

import type { AegisRiskFactor, AegisRiskScore } from "./types";

const SEVERITY_VALUE: Record<Severity, number> = {
  critical: 1,
  high: 0.8,
  medium: 0.55,
  low: 0.3,
  info: 0.1,
};

const EXPLOITABILITY_VALUE: Record<Exploitability, number> = {
  exploitable: 1,
  reachable: 0.7,
  theoretical: 0.3,
  "not-exploitable": 0.05,
  unknown: 0.4,
};

export type ExposureLevel = "internet" | "authenticated" | "internal" | "unknown";
export type AssetImportance = "crown_jewel" | "high" | "standard" | "low" | "unknown";

const EXPOSURE_VALUE: Record<ExposureLevel, number> = {
  internet: 1,
  authenticated: 0.65,
  internal: 0.35,
  unknown: 0.5,
};

const ASSET_VALUE: Record<AssetImportance, number> = {
  crown_jewel: 1,
  high: 0.8,
  standard: 0.5,
  low: 0.25,
  unknown: 0.5,
};

export interface AegisRiskInput {
  severity: Severity;
  exploitability?: Exploitability | null;
  cvss_score?: number | null;
  epss_score?: number | null;
  in_kev?: boolean | null;
  exposure?: ExposureLevel;
  asset_importance?: AssetImportance;
}

export function aegisRiskBand(score: number): RiskLevel {
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 40) return "medium";
  if (score > 0) return "low";
  return "none";
}

export function aegisRiskScore(input: AegisRiskInput): AegisRiskScore {
  const severityValue = SEVERITY_VALUE[input.severity] ?? 0.4;
  const cvssValue = input.cvss_score != null ? Math.min(input.cvss_score, 10) / 10 : severityValue;
  const baseValue = (severityValue + cvssValue) / 2;
  const exploitValue = EXPLOITABILITY_VALUE[input.exploitability ?? "unknown"] ?? 0.4;
  const exposureValue = EXPOSURE_VALUE[input.exposure ?? "unknown"];
  const assetValue = ASSET_VALUE[input.asset_importance ?? "unknown"];
  const intelValue = input.in_kev
    ? 1
    : input.epss_score != null
      ? Math.min(Math.max(input.epss_score, 0), 1)
      : 0.2;

  const weights: { label: string; weight: number; value: number; detail: string }[] = [
    {
      label: "Severity & CVSS",
      weight: 0.3,
      value: baseValue,
      detail: `${input.severity}${input.cvss_score != null ? ` · CVSS ${input.cvss_score}` : " · no CVSS"}`,
    },
    {
      label: "Exploitability",
      weight: 0.3,
      value: exploitValue,
      detail: input.exploitability ?? "unknown",
    },
    {
      label: "Exposure",
      weight: 0.15,
      value: exposureValue,
      detail: input.exposure ?? "unknown",
    },
    {
      label: "Asset importance",
      weight: 0.15,
      value: assetValue,
      detail: (input.asset_importance ?? "unknown").replace("_", " "),
    },
    {
      label: "Threat intelligence",
      weight: 0.1,
      value: intelValue,
      detail: input.in_kev
        ? "Listed in CISA KEV — actively exploited"
        : input.epss_score != null
          ? `EPSS ${(input.epss_score * 100).toFixed(1)}%`
          : "No live exploitation signal",
    },
  ];

  const factors: AegisRiskFactor[] = weights.map((w) => ({
    label: w.label,
    weight: w.weight,
    value: Number(w.value.toFixed(3)),
    contribution: Number((w.weight * w.value * 100).toFixed(1)),
    detail: w.detail,
  }));

  const score = Number(factors.reduce((sum, f) => sum + f.contribution, 0).toFixed(1));

  return { score, band: aegisRiskBand(score), factors };
}

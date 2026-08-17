/**
 * CISA Known Exploited Vulnerabilities (KEV) catalog access.
 *
 * The catalog ships as a static JSON document under /data/cisa-kev.json and is
 * fetched lazily (only when a KEV-aware view is opened) then memoized for the
 * lifetime of the tab, so repeated lookups and correlations are instant.
 */

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string | null;
  knownRansomwareCampaignUse: string | null;
  cwes: string[];
}

export interface KevCatalog {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

let cache: KevCatalog | null = null;
let inflight: Promise<KevCatalog> | null = null;

export async function loadKevCatalog(): Promise<KevCatalog> {
  if (cache) return cache;
  if (inflight) return inflight;
  inflight = fetch("/data/cisa-kev.json")
    .then((res) => {
      if (!res.ok) throw new Error(`Failed to load KEV catalog (${res.status})`);
      return res.json() as Promise<KevCatalog>;
    })
    .then((data) => {
      cache = data;
      inflight = null;
      return data;
    })
    .catch((err) => {
      inflight = null;
      throw err;
    });
  return inflight;
}

export function indexByCve(catalog: KevCatalog): Map<string, KevEntry> {
  const map = new Map<string, KevEntry>();
  for (const entry of catalog.vulnerabilities) {
    map.set(entry.cveID.toUpperCase(), entry);
  }
  return map;
}

/** Pull every CVE id out of arbitrary text (findings, dependency vulns, notes). */
export function extractCves(text: string): string[] {
  const matches = text.toUpperCase().match(/CVE-\d{4}-\d{4,7}/g);
  return matches ? Array.from(new Set(matches)) : [];
}

/**
 * EPSS is not part of the KEV catalog. Until a live EPSS feed is wired in, an
 * exploitation-likelihood proxy is derived from KEV membership signals so the
 * UI never shows a fabricated precise probability.
 */
export function kevExploitationSignal(entry: KevEntry): {
  label: "very high" | "high";
  ransomware: boolean;
  ageDays: number;
} {
  const ransomware = (entry.knownRansomwareCampaignUse || "").toLowerCase() === "known";
  const ageDays = Math.max(
    0,
    Math.round((Date.now() - new Date(entry.dateAdded).getTime()) / 86_400_000),
  );
  return { label: ransomware ? "very high" : "high", ransomware, ageDays };
}

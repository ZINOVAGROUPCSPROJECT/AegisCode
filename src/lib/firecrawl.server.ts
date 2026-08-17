/**
 * Firecrawl access (server-only).
 *
 * The connection is gateway-backed, so every call is routed through the
 * Lovable connector gateway with credentials that never reach the browser.
 */

const GATEWAY = "https://connector-gateway.lovable.dev/firecrawl/v2";

export class FirecrawlError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "FirecrawlError";
    this.status = status;
  }
}

function headers(): Record<string, string> {
  const lovableKey = process.env["LOVABLE_API_KEY"];
  const connectionKey = process.env["FIRECRAWL_API_KEY"];
  if (!lovableKey || !connectionKey) {
    throw new FirecrawlError("Web research is not configured on this deployment.", 503);
  }
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${lovableKey}`,
    "X-Connection-Api-Key": connectionKey,
  };
}

async function call<T>(path: string, body: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${GATEWAY}${path}`, { method: "POST", headers: headers(), body: JSON.stringify(body) });
  } catch (error) {
    throw new FirecrawlError(
      `Could not reach the web research service: ${error instanceof Error ? error.message : String(error)}`,
      502,
    );
  }
  const raw = await res.text();
  if (!res.ok) {
    throw new FirecrawlError(`Web research failed [${res.status}]: ${raw.slice(0, 400)}`, res.status);
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new FirecrawlError("Web research returned an unreadable response.", 502);
  }
}

export interface WebSource {
  title: string;
  url: string;
  snippet: string;
}

interface SearchResponse {
  data?: { web?: SearchItem[] } | SearchItem[];
}
interface SearchItem {
  url?: string;
  title?: string;
  description?: string;
  markdown?: string;
}

const clip = (value: string, max: number) => (value.length > max ? `${value.slice(0, max)}…` : value);

/** Web search with light content scraping, trimmed to a model-friendly size. */
export async function firecrawlSearch(query: string, limit = 5): Promise<WebSource[]> {
  const payload = await call<SearchResponse>("/search", {
    query,
    limit: Math.min(Math.max(limit, 1), 10),
    scrapeOptions: { formats: ["markdown"] },
  });
  const items = Array.isArray(payload.data) ? payload.data : (payload.data?.web ?? []);
  return items
    .filter((i): i is SearchItem & { url: string } => Boolean(i?.url))
    .map((i) => ({
      title: i.title || i.url,
      url: i.url,
      snippet: clip((i.markdown || i.description || "").replace(/\s+/g, " ").trim(), 2500),
    }));
}

interface ScrapeResponse {
  markdown?: string;
  summary?: string;
  metadata?: { title?: string; sourceURL?: string };
  data?: { markdown?: string; summary?: string; metadata?: { title?: string; sourceURL?: string } };
}

/** Scrape one page as clean markdown. */
export async function firecrawlScrape(url: string): Promise<WebSource> {
  const payload = await call<ScrapeResponse>("/scrape", {
    url,
    formats: ["markdown"],
    onlyMainContent: true,
  });
  const doc = payload.data ?? payload;
  return {
    title: doc.metadata?.title || url,
    url: doc.metadata?.sourceURL || url,
    snippet: clip((doc.markdown || doc.summary || "").replace(/\s+/g, " ").trim(), 12_000),
  };
}

/** Renders sources into a compact, citation-friendly block for the model. */
export function formatSources(sources: WebSource[]): string {
  if (!sources.length) return "";
  return sources
    .map((s, i) => `[${i + 1}] ${s.title}\nURL: ${s.url}\n${s.snippet}`)
    .join("\n\n---\n\n");
}
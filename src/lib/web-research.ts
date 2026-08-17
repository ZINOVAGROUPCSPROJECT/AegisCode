import { webResearch } from "./firecrawl.functions";

export interface WebSource {
  title: string;
  url: string;
  snippet: string;
}

export interface WebResearchResult {
  sources: WebSource[];
  context: string;
}

export class WebResearchError extends Error {}

/**
 * Runs Firecrawl web research through the authenticated server boundary.
 * Callers only invoke this when the user turned web search on.
 */
export async function researchWeb(input: {
  query: string;
  limit?: number;
  url?: string;
}): Promise<WebResearchResult> {
  let res: Awaited<ReturnType<typeof webResearch>>;
  try {
    res = await webResearch({
      data: {
        query: input.query.slice(0, 400),
        ...(input.limit ? { limit: input.limit } : {}),
        ...(input.url ? { url: input.url } : {}),
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new WebResearchError(
      /Unexpected token|JSON/i.test(message)
        ? "The web research service returned an unexpected response."
        : message || "Web research could not be started.",
    );
  }
  if (!res.ok) throw new WebResearchError(res.error);
  return { sources: res.sources, context: res.context };
}
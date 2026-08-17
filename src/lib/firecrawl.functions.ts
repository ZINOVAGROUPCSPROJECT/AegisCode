import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { z } from "zod";

const schema = z.object({
  query: z.string().min(2).max(400),
  limit: z.number().int().min(1).max(10).optional(),
  /** Optional explicit page to scrape instead of / in addition to searching. */
  url: z.string().url().max(2000).optional(),
});

export type WebResearchResponse =
  | { ok: true; sources: { title: string; url: string; snippet: string }[]; context: string }
  | { ok: false; error: string; status: number };

/**
 * Authenticated web-research boundary. Only runs when the user explicitly
 * enables web search in the UI, so no request leaves the app silently.
 */
export const webResearch = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => schema.parse(data))
  .handler(async ({ data }): Promise<WebResearchResponse> => {
    const { firecrawlSearch, firecrawlScrape, formatSources, FirecrawlError } = await import("./firecrawl.server");
    try {
      const sources = data.url
        ? [await firecrawlScrape(data.url)]
        : await firecrawlSearch(data.query, data.limit ?? 5);
      return { ok: true, sources, context: formatSources(sources) };
    } catch (error) {
      if (error instanceof FirecrawlError) return { ok: false, error: error.message, status: error.status };
      console.error("[AegisCode WebResearch]", error);
      return { ok: false, error: "Web research failed unexpectedly.", status: 500 };
    }
  });
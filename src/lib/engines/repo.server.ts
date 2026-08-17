/**
 * Repository ingestion + vulnerability intelligence lookups (server side).
 *
 * GitHub/GitLab public (or token-authorized) APIs are used to enumerate the
 * default-branch tree and download the text files the SAST engine can read.
 * OSV.dev supplies dependency advisories and FIRST supplies EPSS scores.
 */

export interface RepoRef {
  provider: "github" | "gitlab";
  owner: string;
  repo: string;
  ref?: string | undefined;
  token?: string | undefined;
}

export interface RepoFile {
  path: string;
  content: string;
  size: number;
}

export interface RepoSnapshot {
  provider: string;
  label: string;
  ref: string;
  commitSha: string;
  files: RepoFile[];
  totalFiles: number;
  skipped: number;
  truncated: boolean;
  manifests: RepoFile[];
}

const TEXT_EXT =
  /\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|java|kt|cs|rs|scala|swift|sql|sh|bash|yml|yaml|json|toml|ini|env|conf|cfg|tf|xml|html|vue|svelte|gradle|md)$/i;
const MANIFEST =
  /(^|\/)(package\.json|package-lock\.json|requirements\.txt|pyproject\.toml|go\.mod|Gemfile(\.lock)?|Cargo\.toml|pom\.xml|composer\.json)$/i;
const SKIP =
  /(^|\/)(node_modules|dist|build|out|coverage|vendor|\.git|\.next|\.cache|__pycache__|target|\.venv)(\/|$)|\.min\.(js|css)$|\.map$/;

const MAX_FILES = 400;
const MAX_FILE_BYTES = 220_000;

function authHeaders(ref: RepoRef): Record<string, string> {
  const h: Record<string, string> = { "User-Agent": "AegisCode-Scanner/1.0", Accept: "application/vnd.github+json" };
  if (ref.token) {
    h[ref.provider === "github" ? "Authorization" : "PRIVATE-TOKEN"] =
      ref.provider === "github" ? `Bearer ${ref.token}` : ref.token;
  }
  return h;
}

/** Accepts a full URL or `owner/repo` and normalizes it. */
export function parseRepoInput(input: string, token?: string): RepoRef {
  const trimmed = input.trim().replace(/\.git$/, "");
  const url = trimmed.match(/^https?:\/\/([^/]+)\/(.+)$/);
  if (url) {
    const host = url[1]!.toLowerCase();
    const parts = url[2]!.split("/").filter(Boolean);
    const provider: RepoRef["provider"] = host.includes("gitlab") ? "gitlab" : "github";
    if (provider === "gitlab") {
      const treeIdx = parts.indexOf("-");
      const pathParts = treeIdx === -1 ? parts : parts.slice(0, treeIdx);
      return {
        provider,
        owner: pathParts.slice(0, -1).join("/"),
        repo: pathParts[pathParts.length - 1] ?? "",
        token,
      };
    }
    return { provider, owner: parts[0] ?? "", repo: parts[1] ?? "", ref: parts[3], token };
  }
  const parts = trimmed.split("/").filter(Boolean);
  return { provider: "github", owner: parts[0] ?? "", repo: parts[1] ?? "", token };
}

export async function fetchRepoSnapshot(ref: RepoRef): Promise<RepoSnapshot> {
  if (!ref.owner || !ref.repo) throw new Error("Provide a repository as owner/repo or a full repository URL.");
  return ref.provider === "github" ? fetchGithub(ref) : fetchGitlab(ref);
}

async function json<T>(url: string, headers: Record<string, string>): Promise<T> {
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const text = (await res.text()).slice(0, 200);
    if (res.status === 404) throw new Error("Repository or branch not found. Private repos need an access token.");
    if (res.status === 401 || res.status === 403)
      throw new Error(`Access denied by the provider (${res.status}). Add a token with read access. ${text}`);
    throw new Error(`Provider error ${res.status}: ${text}`);
  }
  return (await res.json()) as T;
}

async function fetchGithub(ref: RepoRef): Promise<RepoSnapshot> {
  const headers = authHeaders(ref);
  const api = `https://api.github.com/repos/${ref.owner}/${ref.repo}`;
  const meta = await json<{ default_branch: string }>(api, headers);
  const branch = ref.ref || meta.default_branch || "main";
  const commit = await json<{ sha: string; commit: { message: string } }>(
    `${api}/commits/${encodeURIComponent(branch)}`,
    headers,
  );
  const tree = await json<{ tree: { path: string; type: string; size?: number }[]; truncated: boolean }>(
    `${api}/git/trees/${commit.sha}?recursive=1`,
    headers,
  );

  const candidates = tree.tree.filter(
    (n) => n.type === "blob" && !SKIP.test(n.path) && (TEXT_EXT.test(n.path) || MANIFEST.test(n.path)),
  );
  const selected = rank(candidates.map((c) => ({ path: c.path, size: c.size ?? 0 })));
  const files = await downloadAll(
    selected,
    (p) => `https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${commit.sha}/${p}`,
    ref.token ? { Authorization: `Bearer ${ref.token}` } : {},
  );

  return {
    provider: "github",
    label: `${ref.owner}/${ref.repo}`,
    ref: branch,
    commitSha: commit.sha,
    files,
    totalFiles: candidates.length,
    skipped: tree.tree.length - candidates.length,
    truncated: tree.truncated || candidates.length > selected.length,
    manifests: files.filter((f) => MANIFEST.test(f.path)),
  };
}

async function fetchGitlab(ref: RepoRef): Promise<RepoSnapshot> {
  const headers = authHeaders(ref);
  const project = encodeURIComponent(`${ref.owner}/${ref.repo}`);
  const api = `https://gitlab.com/api/v4/projects/${project}`;
  const meta = await json<{ default_branch: string }>(api, headers);
  const branch = ref.ref || meta.default_branch || "main";
  const commits = await json<{ id: string }[]>(`${api}/repository/commits?ref_name=${encodeURIComponent(branch)}&per_page=1`, headers);
  const commitSha = commits[0]?.id ?? branch;

  const nodes: { path: string; type: string }[] = [];
  for (let page = 1; page <= 6; page++) {
    const batch = await json<{ path: string; type: string }[]>(
      `${api}/repository/tree?recursive=true&per_page=100&page=${page}&ref=${encodeURIComponent(branch)}`,
      headers,
    );
    nodes.push(...batch);
    if (batch.length < 100) break;
  }
  const candidates = nodes.filter(
    (n) => n.type === "blob" && !SKIP.test(n.path) && (TEXT_EXT.test(n.path) || MANIFEST.test(n.path)),
  );
  const selected = rank(candidates.map((c) => ({ path: c.path, size: 0 })));
  const files = await downloadAll(
    selected,
    (p) => `${api}/repository/files/${encodeURIComponent(p)}/raw?ref=${encodeURIComponent(branch)}`,
    headers,
  );

  return {
    provider: "gitlab",
    label: `${ref.owner}/${ref.repo}`,
    ref: branch,
    commitSha,
    files,
    totalFiles: candidates.length,
    skipped: nodes.length - candidates.length,
    truncated: candidates.length > selected.length,
    manifests: files.filter((f) => MANIFEST.test(f.path)),
  };
}

/** Manifests and source under src/app/lib get priority when the repo is large. */
function rank(files: { path: string; size: number }[]): { path: string; size: number }[] {
  const score = (p: string) => {
    if (MANIFEST.test(p)) return 0;
    if (/^(src|app|lib|api|server|services|routes|pages|functions)\//.test(p)) return 1;
    if (/\.(md|json|yml|yaml|xml|html)$/i.test(p)) return 3;
    return 2;
  };
  return files
    .filter((f) => f.size <= MAX_FILE_BYTES)
    .sort((a, b) => score(a.path) - score(b.path) || a.path.localeCompare(b.path))
    .slice(0, MAX_FILES);
}

async function downloadAll(
  files: { path: string }[],
  urlFor: (path: string) => string,
  headers: Record<string, string>,
): Promise<RepoFile[]> {
  const out: RepoFile[] = [];
  const concurrency = 12;
  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(async (f) => {
        try {
          const res = await fetch(urlFor(f.path), { headers: { "User-Agent": "AegisCode-Scanner/1.0", ...headers } });
          if (!res.ok) return null;
          const text = (await res.text()).slice(0, MAX_FILE_BYTES);
          return { path: f.path, content: text, size: text.length };
        } catch {
          return null;
        }
      }),
    );
    out.push(...results.filter((r): r is RepoFile => r !== null));
  }
  return out;
}

// ---------------------------------------------------------------- OSV / EPSS

export interface OsvVuln {
  id: string;
  aliases: string[];
  summary: string;
  details?: string;
  published?: string;
  severity?: { type: string; score: string }[];
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
    database_specific?: { severity?: string };
  }[];
  database_specific?: { severity?: string; cvss?: { score?: number } };
}

export async function osvQuery(
  packages: { name: string; version: string; ecosystem: string }[],
): Promise<Record<string, OsvVuln[]>> {
  const out: Record<string, OsvVuln[]> = {};
  const batchSize = 60;
  for (let i = 0; i < packages.length; i += batchSize) {
    const batch = packages.slice(i, i + batchSize);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: batch.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          ...(p.version && p.version !== "*" ? { version: p.version } : {}),
        })),
      }),
    });
    if (!res.ok) continue;
    const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
    const ids = new Map<string, string[]>();
    (data.results ?? []).forEach((r, idx) => {
      const key = batch[idx];
      if (!key || !r.vulns?.length) return;
      ids.set(
        `${key.ecosystem}|${key.name}`,
        r.vulns.map((v) => v.id).slice(0, 12),
      );
    });
    const uniqueIds = [...new Set([...ids.values()].flat())];
    const details = new Map<string, OsvVuln>();
    const conc = 10;
    for (let j = 0; j < uniqueIds.length; j += conc) {
      const chunk = uniqueIds.slice(j, j + conc);
      const fetched = await Promise.all(
        chunk.map(async (id) => {
          try {
            const r = await fetch(`https://api.osv.dev/v1/vulns/${id}`);
            return r.ok ? ((await r.json()) as OsvVuln) : null;
          } catch {
            return null;
          }
        }),
      );
      fetched.forEach((v) => v && details.set(v.id, v));
    }
    for (const [key, list] of ids) {
      out[key] = list.map((id) => details.get(id)).filter((v): v is OsvVuln => !!v);
    }
  }
  return out;
}

export async function epssQuery(cves: string[]): Promise<Record<string, { score: number; percentile: number }>> {
  const out: Record<string, { score: number; percentile: number }> = {};
  const unique = [...new Set(cves.filter((c) => /^CVE-\d{4}-\d{4,7}$/i.test(c)))];
  const batch = 90;
  for (let i = 0; i < unique.length; i += batch) {
    const slice = unique.slice(i, i + batch);
    try {
      const res = await fetch(`https://api.first.org/data/v1/epss?cve=${slice.join(",")}`);
      if (!res.ok) continue;
      const data = (await res.json()) as { data?: { cve: string; epss: string; percentile: string }[] };
      for (const row of data.data ?? []) {
        out[row.cve.toUpperCase()] = { score: Number(row.epss), percentile: Number(row.percentile) };
      }
    } catch {
      // EPSS is enrichment only — a failure must not fail the scan.
    }
  }
  return out;
}

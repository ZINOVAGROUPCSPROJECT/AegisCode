/**
 * Real DAST engine (server side).
 *
 * Performs safe, non-destructive HTTP probes against an authorized target:
 * header hardening, cookie flags, CORS reflection, information disclosure paths,
 * HTTP method exposure, verbose error leakage and TLS enforcement. Every verdict
 * is derived from an actual response — never from model reasoning.
 *
 * Safety rules enforced here:
 *  - the caller must explicitly assert authorization
 *  - only GET/HEAD/OPTIONS requests are issued
 *  - loopback, link-local and RFC1918 targets are refused (SSRF guard)
 *  - one request per probe, hard timeout, redirects not followed blindly
 */

export type Verdict = "confirmed" | "refuted" | "inconclusive";
export type ProbeSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface DastProbe {
  name: string;
  category: string;
  request: string;
  expected_signal: string;
  observed_signal: string;
  verdict: Verdict;
  severity: ProbeSeverity;
  classification: "observed" | "verified" | "inferred" | "unknown";
  cwe?: string;
  remediation?: string;
  status?: number;
}

export interface DastEngineResult {
  target: string;
  probes: DastProbe[];
  findings: {
    title: string;
    severity: ProbeSeverity;
    cwe: string | null;
    confirmed_at_runtime: boolean;
    confidence: number;
    evidence: { type: string; snippet: string; explanation: string; classification: "observed" | "verified" }[];
    reproduction: string;
    impact: string;
    remediation: string;
  }[];
  summary: {
    probes_run: number;
    confirmed: number;
    refuted: number;
    inconclusive: number;
    risk: "critical" | "high" | "medium" | "low" | "unknown";
  };
  runtime_notes: string;
}

const PRIVATE_HOST =
  /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|.*\.internal|.*\.local)$/i;

const DISCLOSURE_PATHS: { path: string; label: string; severity: ProbeSeverity; cwe: string; marker: RegExp }[] = [
  { path: "/.env", label: "Environment file exposed", severity: "critical", cwe: "CWE-538", marker: /^[A-Z0-9_]+=|APP_KEY|SECRET|PASSWORD/m },
  { path: "/.git/HEAD", label: "Git metadata exposed", severity: "high", cwe: "CWE-527", marker: /ref:\s*refs\// },
  { path: "/.aws/credentials", label: "Cloud credentials exposed", severity: "critical", cwe: "CWE-538", marker: /aws_access_key_id/i },
  { path: "/server-status", label: "Apache status page exposed", severity: "medium", cwe: "CWE-200", marker: /Apache Server Status/i },
  { path: "/actuator/env", label: "Spring Actuator env exposed", severity: "high", cwe: "CWE-200", marker: /propertySources|systemEnvironment/ },
  { path: "/phpinfo.php", label: "phpinfo() exposed", severity: "high", cwe: "CWE-200", marker: /phpinfo\(\)|PHP Version/i },
  { path: "/swagger.json", label: "API schema publicly readable", severity: "low", cwe: "CWE-200", marker: /"(swagger|openapi)"\s*:/ },
  { path: "/api-docs", label: "API docs publicly readable", severity: "low", cwe: "CWE-200", marker: /swagger|openapi|redoc/i },
  { path: "/.well-known/security.txt", label: "security.txt present", severity: "info", cwe: "CWE-1059", marker: /Contact:/i },
  { path: "/wp-config.php.bak", label: "Backup config exposed", severity: "critical", cwe: "CWE-530", marker: /DB_PASSWORD|define\(/ },
];

interface FetchOutcome {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
  ms: number;
}

async function probeFetch(url: string, init: RequestInit = {}, maxBytes = 4096): Promise<FetchOutcome> {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  try {
    const res = await fetch(url, {
      redirect: "manual",
      ...init,
      headers: { "User-Agent": "AegisCode-DAST/1.0 (authorized security test)", ...(init.headers ?? {}) },
      signal: controller.signal,
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    let body = "";
    try {
      body = (await res.text()).slice(0, maxBytes);
    } catch {
      body = "";
    }
    return { ok: true, status: res.status, headers, body, ms: Date.now() - started };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      headers: {},
      body: "",
      error: err instanceof Error ? err.message : String(err),
      ms: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

function headerProbe(
  name: string,
  header: string,
  res: FetchOutcome,
  severity: ProbeSeverity,
  cwe: string,
  expected: string,
  remediation: string,
): DastProbe {
  const value = res.headers[header];
  return {
    name,
    category: "Security headers",
    request: `GET / (inspecting ${header})`,
    expected_signal: expected,
    observed_signal: value ? `${header}: ${value}` : `${header} header absent`,
    verdict: value ? "refuted" : "confirmed",
    severity,
    classification: "observed",
    cwe,
    remediation,
    status: res.status,
  };
}

export async function runRealDast(rawTarget: string, authorized: boolean): Promise<DastEngineResult> {
  if (!authorized) throw new Error("You must confirm you are authorized to test this target.");
  let url: URL;
  try {
    url = new URL(rawTarget.includes("://") ? rawTarget : `https://${rawTarget}`);
  } catch {
    throw new Error("Enter a valid target URL, e.g. https://staging.example.com");
  }
  if (!/^https?:$/.test(url.protocol)) throw new Error("Only http:// and https:// targets are supported.");
  if (PRIVATE_HOST.test(url.hostname)) {
    throw new Error("Internal, loopback and private-range targets are blocked to prevent SSRF abuse.");
  }

  const origin = url.origin;
  const base = await probeFetch(url.toString());
  if (!base.ok) {
    throw new Error(`Target unreachable: ${base.error ?? "no response"}`);
  }

  const probes: DastProbe[] = [];

  probes.push({
    name: "Reachability & response fingerprint",
    category: "Recon",
    request: `GET ${url.pathname || "/"}`,
    expected_signal: "A successful HTTP response from the target",
    observed_signal: `HTTP ${base.status} in ${base.ms}ms · server: ${base.headers["server"] ?? "not disclosed"} · powered-by: ${
      base.headers["x-powered-by"] ?? "not disclosed"
    }`,
    verdict: "refuted",
    severity: "info",
    classification: "observed",
    status: base.status,
  });

  // TLS enforcement
  if (url.protocol === "https:") {
    const httpRes = await probeFetch(`http://${url.host}/`);
    const location = httpRes.headers["location"] ?? "";
    const redirects = httpRes.status >= 300 && httpRes.status < 400 && /^https:/i.test(location);
    probes.push({
      name: "HTTP → HTTPS redirect",
      category: "Transport security",
      request: `GET http://${url.host}/`,
      expected_signal: "Cleartext request is redirected to https://",
      observed_signal: httpRes.ok
        ? `HTTP ${httpRes.status}${location ? ` → ${location}` : " with no redirect"}`
        : `cleartext port closed (${httpRes.error})`,
      verdict: httpRes.ok && !redirects ? "confirmed" : "refuted",
      severity: "medium",
      classification: "observed",
      cwe: "CWE-319",
      remediation: "Redirect all HTTP traffic to HTTPS and serve HSTS.",
      status: httpRes.status,
    });
  }

  probes.push(
    headerProbe(
      "HSTS enforced",
      "strict-transport-security",
      base,
      "medium",
      "CWE-319",
      "Strict-Transport-Security present with a long max-age",
      "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    ),
    headerProbe(
      "Content Security Policy",
      "content-security-policy",
      base,
      "medium",
      "CWE-1021",
      "Content-Security-Policy restricts script sources",
      "Ship a CSP with explicit script-src and object-src 'none'.",
    ),
    headerProbe(
      "Clickjacking protection",
      "x-frame-options",
      base,
      "low",
      "CWE-1021",
      "X-Frame-Options or CSP frame-ancestors present",
      "Set `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    ),
    headerProbe(
      "MIME sniffing protection",
      "x-content-type-options",
      base,
      "low",
      "CWE-430",
      "X-Content-Type-Options: nosniff",
      "Set `X-Content-Type-Options: nosniff`.",
    ),
    headerProbe(
      "Referrer policy",
      "referrer-policy",
      base,
      "low",
      "CWE-200",
      "Referrer-Policy limits cross-origin referrer leakage",
      "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
  );

  // Technology disclosure
  const banner = [base.headers["server"], base.headers["x-powered-by"], base.headers["x-aspnet-version"]]
    .filter(Boolean)
    .join(" · ");
  probes.push({
    name: "Technology banner disclosure",
    category: "Information disclosure",
    request: "GET / (response headers)",
    expected_signal: "No server/framework version headers",
    observed_signal: banner || "no technology banners returned",
    verdict: /\d/.test(banner) ? "confirmed" : "refuted",
    severity: "low",
    classification: "observed",
    cwe: "CWE-200",
    remediation: "Strip Server/X-Powered-By version details at the edge.",
    status: base.status,
  });

  // Cookie flags
  const setCookie = base.headers["set-cookie"] ?? "";
  if (setCookie) {
    const missing = [
      !/httponly/i.test(setCookie) && "HttpOnly",
      !/secure/i.test(setCookie) && "Secure",
      !/samesite/i.test(setCookie) && "SameSite",
    ].filter(Boolean);
    probes.push({
      name: "Session cookie flags",
      category: "Session management",
      request: "GET / (inspecting Set-Cookie)",
      expected_signal: "Cookies set with HttpOnly, Secure and SameSite",
      observed_signal: missing.length ? `missing: ${missing.join(", ")}` : "all protective flags present",
      verdict: missing.length ? "confirmed" : "refuted",
      severity: "medium",
      classification: "observed",
      cwe: "CWE-1004",
      remediation: "Set HttpOnly, Secure and SameSite=Lax on session cookies.",
      status: base.status,
    });
  }

  // CORS reflection
  const cors = await probeFetch(origin + "/", { headers: { Origin: "https://aegiscode-probe.example" } });
  const acao = cors.headers["access-control-allow-origin"] ?? "";
  const acac = cors.headers["access-control-allow-credentials"] ?? "";
  const reflected = acao === "https://aegiscode-probe.example" || acao === "*";
  probes.push({
    name: "CORS origin reflection",
    category: "Access control",
    request: "GET / with Origin: https://aegiscode-probe.example",
    expected_signal: "Untrusted origin is not allowed to read responses",
    observed_signal: acao
      ? `Access-Control-Allow-Origin: ${acao}${acac ? `, Allow-Credentials: ${acac}` : ""}`
      : "no CORS headers returned",
    verdict: reflected && /true/i.test(acac) ? "confirmed" : reflected ? "inconclusive" : "refuted",
    severity: reflected && /true/i.test(acac) ? "high" : "medium",
    classification: "observed",
    cwe: "CWE-942",
    remediation: "Reflect only allowlisted origins and never combine wildcards with credentials.",
    status: cors.status,
  });

  // HTTP methods
  const opts = await probeFetch(origin + "/", { method: "OPTIONS" });
  const allow = opts.headers["allow"] ?? opts.headers["access-control-allow-methods"] ?? "";
  const risky = /(PUT|DELETE|TRACE|PATCH|CONNECT)/i.exec(allow)?.[0];
  probes.push({
    name: "Exposed HTTP methods",
    category: "Configuration",
    request: "OPTIONS /",
    expected_signal: "Only safe methods advertised",
    observed_signal: allow ? `Allow: ${allow}` : "server did not advertise methods",
    verdict: risky ? "confirmed" : allow ? "refuted" : "inconclusive",
    severity: risky === "TRACE" ? "medium" : "low",
    classification: "observed",
    cwe: "CWE-650",
    remediation: "Disable unused verbs (TRACE especially) at the web server or CDN.",
    status: opts.status,
  });

  // Verbose errors / stack traces on a non-existent path
  const bogus = await probeFetch(`${origin}/aegiscode-nonexistent-${Date.now()}`);
  const stack = /(Traceback \(most recent call last\)|at [\w./]+:\d+:\d+|Exception in thread|SQLSTATE|ORA-\d{5}|System\.\w+Exception)/.exec(
    bogus.body,
  );
  probes.push({
    name: "Verbose error disclosure",
    category: "Information disclosure",
    request: "GET /aegiscode-nonexistent-<random>",
    expected_signal: "A generic 404 with no internal details",
    observed_signal: stack
      ? `HTTP ${bogus.status} leaked internals: ${stack[0].slice(0, 120)}`
      : `HTTP ${bogus.status}, no stack trace in body`,
    verdict: stack ? "confirmed" : "refuted",
    severity: "medium",
    classification: "observed",
    cwe: "CWE-209",
    remediation: "Return generic error pages in production and log details server-side.",
    status: bogus.status,
  });

  // Directory listing
  const dirRes = await probeFetch(`${origin}/static/`);
  const listing = /Index of \/|<title>Directory listing for/.test(dirRes.body);
  probes.push({
    name: "Directory listing",
    category: "Information disclosure",
    request: "GET /static/",
    expected_signal: "No autoindex output",
    observed_signal: listing ? `HTTP ${dirRes.status} with autoindex output` : `HTTP ${dirRes.status}, no listing`,
    verdict: listing ? "confirmed" : "refuted",
    severity: "medium",
    classification: "observed",
    cwe: "CWE-548",
    remediation: "Disable autoindex/directory listing on static roots.",
    status: dirRes.status,
  });

  // Sensitive path disclosure (read-only GETs)
  for (const item of DISCLOSURE_PATHS) {
    const res = await probeFetch(origin + item.path, {}, 2048);
    const hit = res.status === 200 && item.marker.test(res.body);
    probes.push({
      name: item.label,
      category: "Information disclosure",
      request: `GET ${item.path}`,
      expected_signal: "404/403 or no sensitive content",
      observed_signal: hit
        ? `HTTP 200 with matching content: ${res.body.slice(0, 100).replace(/\s+/g, " ")}`
        : `HTTP ${res.status || "error"}${res.status === 200 ? " but content did not match" : ""}`,
      verdict: hit ? "confirmed" : "refuted",
      severity: item.severity,
      classification: "observed",
      cwe: item.cwe,
      remediation: `Block ${item.path} at the edge and remove the artifact from the deployment.`,
      status: res.status,
    });
  }

  const confirmed = probes.filter((p) => p.verdict === "confirmed" && p.severity !== "info");
  const findings = confirmed.map((p) => ({
    title: p.name,
    severity: p.severity,
    cwe: p.cwe ?? null,
    confirmed_at_runtime: true,
    confidence: 0.95,
    evidence: [
      {
        type: "http_response",
        snippet: `${p.request}\n→ HTTP ${p.status ?? "?"}\n${p.observed_signal}`,
        explanation: `Observed directly against ${origin}; verdict is based on the live response, not inference.`,
        classification: "observed" as const,
      },
    ],
    reproduction: `curl -sSD - '${origin}${p.request.replace(/^\w+\s+/, "").split(" ")[0] ?? "/"}' -o /dev/null`,
    impact: `${p.category}: ${p.expected_signal} was not satisfied on the live target.`,
    remediation: p.remediation ?? "Harden the affected configuration.",
  }));

  const worst = confirmed.reduce(
    (acc, p) => Math.max(acc, { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[p.severity]),
    0,
  );
  const risk = (["unknown", "low", "low", "medium", "high", "critical"] as const)[worst] ?? "unknown";

  return {
    target: origin,
    probes,
    findings,
    summary: {
      probes_run: probes.length,
      confirmed: confirmed.length,
      refuted: probes.filter((p) => p.verdict === "refuted").length,
      inconclusive: probes.filter((p) => p.verdict === "inconclusive").length,
      risk,
    },
    runtime_notes: `${probes.length} non-destructive probes executed against ${origin} (GET/HEAD/OPTIONS only). ${confirmed.length} issues were confirmed from live responses. Authenticated business-logic tests (IDOR, privilege escalation) require credentials and are not attempted automatically.`,
  };
}

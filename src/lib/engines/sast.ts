/**
 * Deterministic SAST engine.
 *
 * Rules are pure pattern + lightweight structural checks that run entirely in
 * the browser over the fetched repository files. No AI involved: every finding
 * has a concrete file, line, snippet and rule id, so results are reproducible.
 * AI is layered on top afterwards purely to *explain* what the engine found.
 */

export type SastSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SastRule {
  id: string;
  name: string;
  severity: SastSeverity;
  cwe: string;
  /** File extensions the rule applies to; empty = all text files. */
  ext: string[];
  pattern: RegExp;
  /** Optional secondary condition on the matched line (e.g. ignore comments). */
  requires?: RegExp;
  /** If present and matching the line, the match is suppressed. */
  ignoreIf?: RegExp;
  message: string;
  remediation: string;
  confidence: number; // 0..1 deterministic confidence for the pattern class
}

export interface SastFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: SastSeverity;
  cwe: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  message: string;
  remediation: string;
  confidence: number;
  fingerprint: string;
}

export interface SourceFile {
  path: string;
  content: string;
}

const JS = ["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PY = ["py"];
const PHP = ["php"];
const JAVA = ["java", "kt"];
const RB = ["rb"];
const GO = ["go"];
const CS = ["cs"];
const SQLX = ["sql"];
const WEB = [...JS, "html", "vue", "svelte"];

export const SAST_RULES: SastRule[] = [
  // ---------- Injection ----------
  {
    id: "js-eval",
    name: "Dynamic code execution via eval()",
    severity: "high",
    cwe: "CWE-95",
    ext: JS,
    pattern: /\beval\s*\(/g,
    ignoreIf: /\/\/|\/\*|eslint/,
    message: "eval() executes arbitrary code. If any part of the argument is attacker-influenced this is remote code execution.",
    remediation: "Replace eval() with JSON.parse, a lookup table, or an explicit parser.",
    confidence: 0.9,
  },
  {
    id: "js-new-function",
    name: "Code construction via new Function()",
    severity: "high",
    cwe: "CWE-95",
    ext: JS,
    pattern: /new\s+Function\s*\(/g,
    message: "new Function() compiles strings into executable code at runtime.",
    remediation: "Avoid runtime code generation; use static functions or a safe interpreter.",
    confidence: 0.85,
  },
  {
    id: "js-child-process",
    name: "Shell command built from interpolation",
    severity: "critical",
    cwe: "CWE-78",
    ext: JS,
    pattern: /(exec|execSync)\s*\(\s*[`'"][^`'"]*\$\{|(exec|execSync)\s*\(\s*[^,)]*\+/g,
    message: "A shell command is assembled with string interpolation/concatenation — classic OS command injection.",
    remediation: "Use execFile/spawn with an argument array and never interpolate user input into a shell string.",
    confidence: 0.9,
  },
  {
    id: "py-os-system",
    name: "OS command execution with interpolation",
    severity: "critical",
    cwe: "CWE-78",
    ext: PY,
    pattern: /(os\.system|os\.popen|subprocess\.(call|run|Popen))\s*\(\s*(f["']|["'][^"']*["']\s*[%+]|.*\+)/g,
    message: "Shell command built from dynamic data allows OS command injection.",
    remediation: "Pass a list of arguments and shell=False; validate any dynamic component against an allowlist.",
    confidence: 0.88,
  },
  {
    id: "py-eval-exec",
    name: "eval()/exec() on dynamic input",
    severity: "high",
    cwe: "CWE-95",
    ext: PY,
    pattern: /\b(eval|exec)\s*\(\s*(?!["'][^"']*["']\s*\))/g,
    message: "Python eval()/exec() with non-literal input is remote code execution.",
    remediation: "Use ast.literal_eval or explicit parsing.",
    confidence: 0.8,
  },
  {
    id: "sql-string-concat",
    name: "SQL query built by concatenation",
    severity: "critical",
    cwe: "CWE-89",
    ext: [...JS, ...PY, ...PHP, ...JAVA, ...RB, ...GO, ...CS],
    pattern:
      /(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^;\n]{0,160}?(\+\s*\w|\$\{|%s['"]?\s*%|["']\s*\.\s*\$|\|\|\s*\w)/gi,
    ignoreIf: /prepare|placeholder|\?\s*,|:\w+\s*[,)]/i,
    message: "SQL statement is concatenated with variable data instead of using bound parameters — SQL injection.",
    remediation: "Use parameterized queries / prepared statements (e.g. `WHERE id = $1`) or a query builder.",
    confidence: 0.85,
  },
  {
    id: "nosql-where",
    name: "MongoDB $where / dynamic query operator",
    severity: "high",
    cwe: "CWE-943",
    ext: JS,
    pattern: /\$where\s*:|\.\s*mapReduce\s*\(/g,
    message: "$where evaluates JavaScript server-side and enables NoSQL injection.",
    remediation: "Express the filter with standard query operators; never pass raw user input into $where.",
    confidence: 0.8,
  },
  {
    id: "php-shell",
    name: "PHP shell execution",
    severity: "critical",
    cwe: "CWE-78",
    ext: PHP,
    pattern: /\b(shell_exec|passthru|system|exec|popen|proc_open)\s*\(\s*\$/g,
    message: "PHP shell function invoked with a variable argument.",
    remediation: "Use escapeshellarg()/escapeshellcmd() plus an allowlist, or avoid shell calls entirely.",
    confidence: 0.9,
  },
  {
    id: "java-runtime-exec",
    name: "Runtime.exec with concatenation",
    severity: "critical",
    cwe: "CWE-78",
    ext: JAVA,
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/g,
    message: "Command string concatenation in Runtime.exec allows command injection.",
    remediation: "Use ProcessBuilder with a fixed argument list.",
    confidence: 0.9,
  },

  // ---------- XSS / DOM ----------
  {
    id: "js-inner-html",
    name: "innerHTML assignment from variable",
    severity: "medium",
    cwe: "CWE-79",
    ext: WEB,
    pattern: /\.innerHTML\s*=\s*(?!["'`]\s*["'`])/g,
    message: "Writing to innerHTML with dynamic content leads to DOM XSS.",
    remediation: "Use textContent, or sanitize with DOMPurify before insertion.",
    confidence: 0.7,
  },
  {
    id: "react-dangerous-html",
    name: "dangerouslySetInnerHTML",
    severity: "high",
    cwe: "CWE-79",
    ext: JS,
    pattern: /dangerouslySetInnerHTML/g,
    message: "React escape hatch that injects raw HTML into the DOM.",
    remediation: "Render text, or sanitize the HTML with DOMPurify first.",
    confidence: 0.75,
  },
  {
    id: "js-document-write",
    name: "document.write with dynamic data",
    severity: "medium",
    cwe: "CWE-79",
    ext: WEB,
    pattern: /document\.write(ln)?\s*\(/g,
    message: "document.write injects unparsed markup and is a common XSS sink.",
    remediation: "Build nodes with the DOM API instead.",
    confidence: 0.6,
  },
  {
    id: "js-location-sink",
    name: "Navigation to unvalidated URL",
    severity: "medium",
    cwe: "CWE-601",
    ext: WEB,
    pattern: /(location\.href|location\.assign|window\.open)\s*\(?\s*=?\s*[^"'`)\n]*(req\.|params|query|searchParams)/g,
    message: "Redirect target derived from request data enables open redirect / javascript: URL abuse.",
    remediation: "Validate against an allowlist of relative paths or known hosts.",
    confidence: 0.7,
  },

  // ---------- Crypto / secrets ----------
  {
    id: "weak-hash",
    name: "Weak hash algorithm",
    severity: "medium",
    cwe: "CWE-327",
    ext: [],
    pattern: /(createHash\s*\(\s*["'](md5|sha1)["']|hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["'])/gi,
    message: "MD5/SHA-1 are collision-prone and unsuitable for integrity or password use.",
    remediation: "Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.",
    confidence: 0.9,
  },
  {
    id: "insecure-random",
    name: "Insecure randomness for security value",
    severity: "medium",
    cwe: "CWE-338",
    ext: [],
    pattern: /(Math\.random\s*\(\)|random\.random\s*\(\))[^\n]{0,60}(token|secret|password|key|otp|nonce|session|id)/gi,
    message: "Math.random()/random.random() is not cryptographically secure.",
    remediation: "Use crypto.randomUUID(), crypto.getRandomValues(), or secrets.token_urlsafe().",
    confidence: 0.8,
  },
  {
    id: "hardcoded-secret",
    name: "Hardcoded credential",
    severity: "critical",
    cwe: "CWE-798",
    ext: [],
    pattern:
      /(password|passwd|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    ignoreIf: /process\.env|import\.meta\.env|os\.environ|getenv|\{\{|\$\{|example|placeholder|xxx|changeme|your[_-]/i,
    message: "A credential appears to be committed in source.",
    remediation: "Move the value to an environment variable or secret manager and rotate the exposed credential.",
    confidence: 0.7,
  },
  {
    id: "private-key-block",
    name: "Private key material committed",
    severity: "critical",
    cwe: "CWE-798",
    ext: [],
    pattern: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    message: "A private key block is stored in the repository.",
    remediation: "Remove the key, rotate it, and purge it from git history.",
    confidence: 0.99,
  },
  {
    id: "aws-access-key",
    name: "AWS access key id",
    severity: "critical",
    cwe: "CWE-798",
    ext: [],
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
    message: "AWS access key identifier found in source.",
    remediation: "Rotate the key immediately and use IAM roles or a secret store.",
    confidence: 0.95,
  },
  {
    id: "jwt-literal",
    name: "Hardcoded JWT",
    severity: "high",
    cwe: "CWE-798",
    ext: [],
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    message: "A signed JWT is embedded in the code and may still be valid.",
    remediation: "Remove the token, rotate signing keys and fetch tokens at runtime.",
    confidence: 0.85,
  },

  // ---------- Transport / config ----------
  {
    id: "tls-verify-disabled",
    name: "TLS verification disabled",
    severity: "high",
    cwe: "CWE-295",
    ext: [],
    pattern:
      /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)/g,
    message: "Certificate validation is turned off, enabling machine-in-the-middle attacks.",
    remediation: "Keep verification on and install the proper CA chain for internal endpoints.",
    confidence: 0.95,
  },
  {
    id: "http-url",
    name: "Cleartext HTTP endpoint",
    severity: "low",
    cwe: "CWE-319",
    ext: [],
    pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\{)/g,
    message: "Traffic to this endpoint is unencrypted.",
    remediation: "Use https:// for all external endpoints.",
    confidence: 0.6,
  },
  {
    id: "cors-wildcard",
    name: "Permissive CORS policy",
    severity: "medium",
    cwe: "CWE-942",
    ext: [],
    pattern: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["']/g,
    message: "Any origin can read responses from this service.",
    remediation: "Reflect only allowlisted origins, especially when credentials are involved.",
    confidence: 0.85,
  },
  {
    id: "cookie-insecure",
    name: "Cookie without secure flags",
    severity: "medium",
    cwe: "CWE-1004",
    ext: [],
    pattern: /(httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*["']none["'])/gi,
    message: "Session cookie flags weaken protection against theft and CSRF.",
    remediation: "Set httpOnly: true, secure: true and sameSite: 'lax' or 'strict'.",
    confidence: 0.8,
  },
  {
    id: "debug-enabled",
    name: "Debug mode enabled",
    severity: "medium",
    cwe: "CWE-489",
    ext: [],
    pattern: /(DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\([^)]*debug\s*=\s*True)/g,
    message: "Debug mode leaks stack traces and can expose an interactive console.",
    remediation: "Drive debug from environment configuration and disable it in production.",
    confidence: 0.8,
  },

  // ---------- Deserialization / files / SSRF ----------
  {
    id: "insecure-deserialization",
    name: "Insecure deserialization",
    severity: "critical",
    cwe: "CWE-502",
    ext: [],
    pattern: /(pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|unserialize\s*\(\s*\$|ObjectInputStream\s*\()/g,
    message: "Deserializing untrusted data can trigger arbitrary code execution.",
    remediation: "Use JSON, yaml.safe_load, or a signed/validated schema-based format.",
    confidence: 0.9,
  },
  {
    id: "path-traversal",
    name: "Filesystem path from request data",
    severity: "high",
    cwe: "CWE-22",
    ext: [],
    pattern:
      /(readFile(Sync)?|createReadStream|sendFile|open|unlink|writeFile(Sync)?)\s*\([^)]*(req\.(params|query|body)|request\.(args|form)|params\[)/g,
    message: "A file path is built from request input — path traversal risk.",
    remediation: "Resolve against a fixed base directory and reject paths escaping it.",
    confidence: 0.85,
  },
  {
    id: "ssrf-fetch",
    name: "Outbound request to user-controlled URL",
    severity: "high",
    cwe: "CWE-918",
    ext: [],
    pattern:
      /(fetch|axios(\.get|\.post)?|requests\.(get|post)|http\.get|urlopen)\s*\(\s*[^)]*(req\.(params|query|body)|request\.(args|form)|params\[)/g,
    message: "Server-side request built from user input enables SSRF to internal services.",
    remediation: "Allowlist hosts/schemes and block link-local and private ranges.",
    confidence: 0.85,
  },
  {
    id: "xxe",
    name: "XML parser without entity hardening",
    severity: "high",
    cwe: "CWE-611",
    ext: [],
    pattern: /(DocumentBuilderFactory\.newInstance|etree\.parse|libxml_disable_entity_loader\s*\(\s*false)/g,
    message: "XML parsing without disabling external entities allows XXE.",
    remediation: "Disable DTD/external entity resolution (e.g. defusedxml, FEATURE_SECURE_PROCESSING).",
    confidence: 0.6,
  },
  {
    id: "redos",
    name: "Potentially catastrophic regex",
    severity: "medium",
    cwe: "CWE-1333",
    ext: [],
    pattern: /\(\s*[^)]*[+*]\s*\)\s*[+*]/g,
    message: "Nested quantifiers can cause exponential backtracking (ReDoS).",
    remediation: "Simplify the pattern or bound input length before matching.",
    confidence: 0.45,
  },

  // ---------- Access control ----------
  {
    id: "auth-bypass-comment",
    name: "Authorization check disabled",
    severity: "high",
    cwe: "CWE-862",
    ext: [],
    pattern: /(\/\/|#)\s*(TODO|FIXME)?\s*(temporarily\s+)?(disable|skip|bypass)[^\n]{0,40}(auth|permission|acl|rbac)/gi,
    message: "Code comment indicates an intentionally disabled access control check.",
    remediation: "Restore the authorization check and add a regression test.",
    confidence: 0.7,
  },
  {
    id: "idor-direct-id",
    name: "Object lookup by request id without ownership filter",
    severity: "high",
    cwe: "CWE-639",
    ext: [...JS, ...PY],
    pattern: /(findById|findByPk|get_object_or_404|\.eq\(\s*["']id["']\s*,\s*(req|request))/g,
    ignoreIf: /user_id|owner|auth\.uid|current_user/,
    message: "Record fetched purely from a client-supplied id with no ownership constraint — IDOR.",
    remediation: "Scope the query to the authenticated principal (e.g. `where id = ? and user_id = ?`).",
    confidence: 0.65,
  },
  {
    id: "jwt-none-alg",
    name: "JWT signature verification skipped",
    severity: "critical",
    cwe: "CWE-347",
    ext: [],
    pattern: /(jwt\.decode\s*\([^)]*verify\s*[:=]\s*(False|false)|algorithms\s*[:=]\s*\[?\s*["']none["'])/gi,
    message: "JWTs are decoded without verifying the signature — tokens can be forged.",
    remediation: "Always verify with an explicit algorithm allowlist and the correct key.",
    confidence: 0.95,
  },
  {
    id: "sql-raw-supabase",
    name: "Raw SQL/RPC with interpolated argument",
    severity: "high",
    cwe: "CWE-89",
    ext: JS,
    pattern: /\.(rpc|query)\s*\(\s*[`'"][^`'"]*\$\{/g,
    message: "Raw SQL/RPC string interpolation reaches the database driver directly.",
    remediation: "Pass values as parameters instead of interpolating them into SQL.",
    confidence: 0.8,
  },
  {
    id: "logging-sensitive",
    name: "Sensitive data written to logs",
    severity: "low",
    cwe: "CWE-532",
    ext: [],
    pattern: /(console\.log|logger?\.(info|debug|warn)|print)\s*\([^)]*(password|token|secret|apikey|api_key|ssn|credit)/gi,
    message: "Secrets or PII may be persisted to log storage.",
    remediation: "Redact sensitive fields before logging.",
    confidence: 0.7,
  },
];

const SKIP_DIR =
  /(^|\/)(node_modules|dist|build|out|coverage|vendor|\.git|\.next|\.cache|__pycache__|target|bin|obj|public\/data)(\/|$)/;
const SKIP_FILE =
  /(\.min\.(js|css)$|\.map$|-lock\.(json|yaml)$|\.lock$|\.(png|jpe?g|gif|svg|webp|ico|pdf|zip|gz|tar|woff2?|ttf|eot|mp4|mp3|wasm)$)/i;

export function isScannable(path: string): boolean {
  return !SKIP_DIR.test(path) && !SKIP_FILE.test(path);
}

function ext(path: string): string {
  const i = path.lastIndexOf(".");
  return i === -1 ? "" : path.slice(i + 1).toLowerCase();
}

function hash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export interface SastResult {
  findings: SastFinding[];
  filesScanned: number;
  linesScanned: number;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    rules_triggered: number;
    files_with_findings: number;
  };
}

/** Runs every applicable rule over every file. Purely deterministic. */
export function runSast(files: SourceFile[], maxFindingsPerRule = 40): SastResult {
  const findings: SastFinding[] = [];
  const perRule = new Map<string, number>();
  let filesScanned = 0;
  let linesScanned = 0;

  for (const file of files) {
    if (!isScannable(file.path) || !file.content) continue;
    const e = ext(file.path);
    const lines = file.content.split("\n");
    filesScanned++;
    linesScanned += lines.length;

    for (const rule of SAST_RULES) {
      if (rule.ext.length > 0 && !rule.ext.includes(e)) continue;
      if ((perRule.get(rule.id) ?? 0) >= maxFindingsPerRule) continue;

      for (let li = 0; li < lines.length; li++) {
        const line = lines[li] ?? "";
        if (line.length > 800) continue;
        if (rule.ignoreIf && rule.ignoreIf.test(line)) continue;
        if (rule.requires && !rule.requires.test(line)) continue;

        const re = new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "") + "g");
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
          const count = perRule.get(rule.id) ?? 0;
          if (count >= maxFindingsPerRule) break;
          perRule.set(rule.id, count + 1);
          const fingerprint = hash(`${rule.id}|${file.path}|${line.trim()}`);
          findings.push({
            id: `${rule.id}-${fingerprint}`,
            ruleId: rule.id,
            title: rule.name,
            severity: rule.severity,
            cwe: rule.cwe,
            file: file.path,
            line: li + 1,
            column: m.index + 1,
            snippet: buildSnippet(lines, li),
            message: rule.message,
            remediation: rule.remediation,
            confidence: rule.confidence,
            fingerprint,
          });
          if (m.index === re.lastIndex) re.lastIndex++;
          break; // one finding per rule per line
        }
      }
    }
  }

  const count = (s: SastSeverity) => findings.filter((f) => f.severity === s).length;
  return {
    findings: findings.sort(
      (a, b) => severityWeight(b.severity) - severityWeight(a.severity) || a.file.localeCompare(b.file),
    ),
    filesScanned,
    linesScanned,
    summary: {
      total: findings.length,
      critical: count("critical"),
      high: count("high"),
      medium: count("medium"),
      low: count("low"),
      info: count("info"),
      rules_triggered: new Set(findings.map((f) => f.ruleId)).size,
      files_with_findings: new Set(findings.map((f) => f.file)).size,
    },
  };
}

function buildSnippet(lines: string[], index: number): string {
  const start = Math.max(0, index - 2);
  const end = Math.min(lines.length, index + 3);
  return lines
    .slice(start, end)
    .map((l, i) => `${String(start + i + 1).padStart(4, " ")} | ${l}`)
    .join("\n");
}

export function severityWeight(s: SastSeverity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}

export interface ScanDiff {
  added: SastFinding[];
  fixed: SastFinding[];
  regressed: SastFinding[];
  unchanged: number;
}

/**
 * Compares a new scan against the stored baseline. `regressed` are findings that
 * had previously disappeared (present in history but not in the baseline) — the
 * caller supplies them via `everSeen` so a re-introduced bug is flagged loudly.
 */
export function diffScans(
  baseline: SastFinding[],
  current: SastFinding[],
  everSeen: string[] = [],
): ScanDiff {
  const baseKeys = new Set(baseline.map((f) => f.fingerprint));
  const curKeys = new Set(current.map((f) => f.fingerprint));
  const seen = new Set(everSeen);

  const added = current.filter((f) => !baseKeys.has(f.fingerprint));
  const fixed = baseline.filter((f) => !curKeys.has(f.fingerprint));
  const regressed = added.filter((f) => seen.has(f.fingerprint));
  return {
    added: added.filter((f) => !seen.has(f.fingerprint)),
    fixed,
    regressed,
    unchanged: current.length - added.length,
  };
}

/** Gate decision for CI: fails when findings meet or exceed the threshold. */
export function gateDecision(
  findings: SastFinding[],
  blockOn: SastSeverity,
): { status: "passed" | "failed"; blocking: SastFinding[] } {
  const threshold = severityWeight(blockOn);
  const blocking = findings.filter((f) => severityWeight(f.severity) >= threshold);
  return { status: blocking.length > 0 ? "failed" : "passed", blocking };
}

/** Compact, token-efficient digest handed to the AI explainer. */
export function findingsDigest(findings: SastFinding[], limit = 25): string {
  return findings
    .slice(0, limit)
    .map(
      (f) =>
        `[${f.severity.toUpperCase()}] ${f.ruleId} ${f.cwe} ${f.file}:${f.line} — ${f.title}\n${f.snippet}`,
    )
    .join("\n\n");
}

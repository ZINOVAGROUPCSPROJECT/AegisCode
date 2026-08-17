import { useState, useRef, useEffect, useCallback } from "react";
import {
  Bot,
  X,
  Send,
  Sparkles,
  ShieldAlert,
  Crosshair,
  Network,
  Package,
  Cpu,
  Globe,
  GitCompareArrows,
  Wrench,
  ScanSearch,
  LayoutDashboard,
  FileText,
  GitBranch,
  Loader2,
  AlertCircle,
  ChevronRight,
  Search,
} from "lucide-react";
import { ai } from "@/lib/ai";
import { researchWeb } from "@/lib/web-research";
import { supabase } from "@/lib/db";
import {
  appendMessage,
  clearSession,
  getOrCreateSession,
  loadMessages,
} from "@/lib/chat-history";
import { classNames } from "@/lib/utils";
import { Markdown } from "@/components/Markdown";
import { useAuth } from "@/lib/auth";
import type { PageId } from "@/components/AppShell";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

interface WebSource {
  title: string;
  url: string;
}

interface QuickAction {
  label: string;
  icon: typeof Bot;
  page: PageId;
  prompt: string;
}

const PAGE_CONTEXT: Record<PageId, string> = {
  dashboard: "Dashboard — overview of scans, findings, severity distribution, and accuracy metrics",
  analyze: "Analyze — paste code to run AI vulnerability detection",
  "repo-scan": "Repository Scanner — deterministic SAST engine over a whole GitHub/GitLab repository, with commit-to-commit regression and fix verification",
  "code-security": "Code Security — browse and triage findings from scans",
  "api-security": "API Security — discover endpoints and test for broken auth, IDOR, injection and SSRF",
  dast: "DAST / Runtime — probe the live application to confirm vulnerabilities at runtime",
  secrets: "Secret Detection — find exposed API keys, tokens, passwords and private keys",
  evidence: "Evidence Center — code, data flow, runtime evidence and the reasoning behind each verdict",
  finding: "Finding Details — full detail for one vulnerability: severity, CWE, CVSS, exploitability, evidence, attack path, fix",
  "ci-cd": "CI/CD Gate — scan pull requests and block deployments on dangerous vulnerabilities",
  exploitability: "Exploitability — assess whether findings are actually exploitable in your app",
  "attack-paths": "Attack Paths — visualize multi-step attack paths from findings",
  "supply-chain": "Supply Chain — analyze dependencies for vulnerabilities, poisoning, and blast radius",
  "reverse-engineering": "Reverse Engineering — analyze binary metadata for security-relevant findings",
  "security-graph": "Security Graph — visualize relationships between findings, dependencies, and threat intel",
  kev: "Known Exploited Vulnerabilities — the CISA KEV catalog, ransomware-linked CVEs, and CVE-to-asset correlation against findings, dependencies and threat intel",
  "threat-intel": "Threat Intel — fuse CVE/NVD/OSV/CISA KEV/EPSS intelligence",
  drift: "Drift — detect security-relevant changes between before/after states",
  remediation: "Remediation — generate secure fixes and verify them independently",
  reports: "Reports — generate and export security reports",
  settings: "Settings — configure AI model, preferences, and data management",
};

const QUICK_ACTIONS: QuickAction[] = [
  { label: "Analyze Code", icon: ScanSearch, page: "analyze", prompt: "I want to analyze some code for security vulnerabilities. What should I do?" },
  { label: "Check Exploitability", icon: Crosshair, page: "exploitability", prompt: "How do I assess whether a vulnerability is actually exploitable in my application?" },
  { label: "Attack Paths", icon: Network, page: "attack-paths", prompt: "How can I visualize attack paths from my findings?" },
  { label: "Supply Chain", icon: Package, page: "supply-chain", prompt: "I need to analyze my dependencies for supply chain risks. How does this work?" },
  { label: "Reverse Engineer", icon: Cpu, page: "reverse-engineering", prompt: "I want to reverse engineer a binary. What metadata should I provide?" },
  { label: "Threat Intel", icon: Globe, page: "threat-intel", prompt: "How do I correlate CVEs with threat intelligence feeds?" },
  { label: "Detect Drift", icon: GitCompareArrows, page: "drift", prompt: "I want to detect security-relevant drift between two states of my project." },
  { label: "Remediate", icon: Wrench, page: "remediation", prompt: "How do I generate and verify a secure fix for a vulnerability?" },
];

export function AIAssistant({
  open,
  onClose,
  currentPage,
  onNavigate,
}: {
  open: boolean;
  onClose: () => void;
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
}) {
  const { user } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [contextData, setContextData] = useState<string>("");
  const [webSearch, setWebSearch] = useState(false);
  const [sources, setSources] = useState<WebSource[]>([]);
  const [researching, setResearching] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Chat history lives in the database, scoped to the signed-in user by RLS,
  // so it survives reloads, navigation and cleared browser storage.
  useEffect(() => {
    let cancelled = false;
    if (!user) {
      setSessionId(null);
      setMessages([]);
      return;
    }
    (async () => {
      try {
        const id = await getOrCreateSession();
        if (cancelled || !id) return;
        setSessionId(id);
        const history = await loadMessages(id);
        if (!cancelled && history.length > 0) setMessages(history);
      } catch {
        /* history is best-effort; the assistant must stay usable */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [user?.id]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, loading]);

  useEffect(() => {
    if (open && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);

  // Fetch context data from the current page to give the AI awareness
  const fetchContext = useCallback(async (page: PageId) => {
    try {
      let data = "";
      if (page === "dashboard" || page === "code-security") {
        const { data: scans } = await supabase.from("scans").select("*").order("created_at", { ascending: false }).limit(5);
        const { data: findings } = await supabase.from("findings").select("*").order("created_at", { ascending: false }).limit(10);
        if (scans && scans.length > 0) {
          data += `Recent scans: ${JSON.stringify(scans.map(s => ({ name: s.name, type: s.scan_type, status: s.status, findings: s.summary })), null, 2)}\n`;
        }
        if (findings && findings.length > 0) {
          data += `Recent findings: ${JSON.stringify(findings.map(f => ({ title: f.title, severity: f.severity, cwe: f.cwe, exploitability: f.exploitability, confidence: f.exploit_confidence })), null, 2)}\n`;
        }
      } else if (page === "supply-chain") {
        const { data: deps } = await supabase.from("dependencies").select("*").limit(10);
        if (deps && deps.length > 0) {
          data += `Dependencies: ${JSON.stringify(deps.map(d => ({ name: d.name, version: d.version, risk: d.risk_level, vulns: d.vulnerabilities?.length ?? 0 })), null, 2)}\n`;
        }
      } else if (page === "threat-intel") {
        const { data: intel } = await supabase.from("threat_intel").select("*").limit(10);
        if (intel && intel.length > 0) {
          data += `Threat intel: ${JSON.stringify(intel.map(t => ({ cve: t.cve, source: t.source, cvss: t.cvss_score, in_kev: t.in_kev })), null, 2)}\n`;
        }
      } else if (page === "remediation") {
        const { data: remeds } = await supabase.from("remediations").select("*").limit(5);
        if (remeds && remeds.length > 0) {
          data += `Remediations: ${JSON.stringify(remeds.map(r => ({ status: r.verification_status, model: r.model })), null, 2)}\n`;
        }
      } else if (page === "drift") {
        const { data: drifts } = await supabase.from("drift_records").select("*").limit(5);
        if (drifts && drifts.length > 0) {
          data += `Drift records: ${JSON.stringify(drifts.map(d => ({ type: d.drift_type, severity: d.severity, impact: d.security_impact })), null, 2)}\n`;
        }
      }
      setContextData(data);
    } catch {
      setContextData("");
    }
  }, []);

  useEffect(() => {
    if (open) {
      fetchContext(currentPage);
    }
  }, [open, currentPage, fetchContext]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const userMessage: ChatMessage = { role: "user", content: input.trim() };
    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInput("");
    setLoading(true);
    setError(null);

    try {
      // The session may not have resolved yet on first send — create it now so
      // no message is ever lost from history.
      let activeSession = sessionId;
      if (!activeSession) {
        activeSession = await getOrCreateSession().catch(() => null);
        if (activeSession) setSessionId(activeSession);
      }
      if (activeSession) {
        await appendMessage(activeSession, userMessage, currentPage).catch(() => undefined);
      }
      // Web research only runs when the user explicitly enables it.
      let webBlock = "";
      if (webSearch) {
        setResearching(true);
        try {
          const research = await researchWeb({ query: userMessage.content, limit: 5 });
          setSources(research.sources.map((s) => ({ title: s.title, url: s.url })));
          if (research.context) {
            webBlock = `Live web research results (cite them as [n] with their URL, ignore anything irrelevant):\n${research.context}\n\n`;
          }
        } catch (researchError) {
          setError(
            `Web search unavailable: ${researchError instanceof Error ? researchError.message : "unknown error"}. Answering without it.`,
          );
          setSources([]);
        } finally {
          setResearching(false);
        }
      } else {
        setSources([]);
      }

      const contextPrefix = `Current page: ${currentPage} — ${PAGE_CONTEXT[currentPage]}\n${contextData ? `Relevant data from this page:\n${contextData}\n` : ""}User question: `;
      const messagesWithContext = newMessages.map((m, i) => ({
        role: m.role,
        content: i === 0 ? contextPrefix + m.content : m.content,
      }));
      if (webBlock && messagesWithContext.length > 0) {
        const last = messagesWithContext[messagesWithContext.length - 1]!;
        messagesWithContext[messagesWithContext.length - 1] = {
          role: last.role,
          content: `${webBlock}${last.content}`,
        };
      }

      const response = await ai.chat(messagesWithContext);
      const assistantMessage: ChatMessage = {
        role: "assistant",
        content: typeof response === "string" ? response : JSON.stringify(response, null, 2),
      };
      setMessages([...newMessages, assistantMessage]);
      if (activeSession) {
        await appendMessage(activeSession, assistantMessage, currentPage).catch(() => undefined);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get a response. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleQuickAction = (action: QuickAction) => {
    onNavigate(action.page);
    setInput(action.prompt);
    setTimeout(() => inputRef.current?.focus(), 100);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-end sm:items-stretch">
      {/* Backdrop — click to close on mobile */}
      <div
        className="absolute inset-0 bg-ink-950/60 backdrop-blur-sm animate-fade-in sm:bg-transparent sm:backdrop-blur-none"
        onClick={onClose}
      />

      {/* Assistant panel */}
      <div className="relative z-10 flex h-full w-full max-w-md flex-col animate-slide-in-right sm:h-full skeu-bezel border-l border-ink-700/40">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-ink-700/40 px-4 py-3 bg-brushed-metal">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg skeu-bezel">
              <Bot className="h-5 w-5 text-cyber-400" />
            </div>
            <div>
              <p className="text-sm font-bold text-ink-100 flex items-center gap-1.5">
                Aegis Assistant
                <span className="led text-volt-400 animate-led-pulse" style={{ width: 6, height: 6 }} />
              </p>
              <p className="text-[10px] text-ink-500">Connected to all features</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {messages.length > 0 && (
              <button
                onClick={() => {
                  setMessages([]);
                  setError(null);
                  if (sessionId) void clearSession(sessionId).catch(() => undefined);
                }}
                className="rounded-md px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-ink-400 transition-colors hover:text-danger"
                title="Clear chat history"
              >
                Clear
              </button>
            )}
            <button
              onClick={onClose}
              aria-label="Close assistant"
              className="text-ink-400 hover:text-ink-100 transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Quick actions */}
        {messages.length === 0 && (
          <div className="border-b border-ink-700/40 p-3 max-h-[240px] overflow-y-auto">
            <p className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-500">
              <Sparkles className="h-3 w-3 text-cyber-400" />
              Quick Actions
            </p>
            <div className="grid grid-cols-2 gap-1.5">
              {QUICK_ACTIONS.map((action) => (
                <button
                  key={action.label}
                  onClick={() => handleQuickAction(action)}
                  className="flex items-center gap-2 rounded-lg px-2.5 py-2 text-xs font-medium text-ink-300 transition-all duration-150 skeu-bezel hover:text-cyber-300 text-left"
                >
                  <action.icon className="h-3.5 w-3.5 shrink-0 text-ink-400" />
                  <span className="truncate">{action.label}</span>
                  <ChevronRight className="h-3 w-3 ml-auto text-ink-600" />
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Messages */}
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4 skeu-screen">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center py-8">
              <div className="flex h-14 w-14 items-center justify-center rounded-xl skeu-bezel mb-3">
                <Bot className="h-7 w-7 text-cyber-400" />
              </div>
              <p className="text-sm font-semibold text-ink-200">Ask me anything about your security</p>
              <p className="mt-1 max-w-[260px] text-xs text-ink-500">
                I can see your current page data and help you analyze code, assess exploitability, investigate findings, remediate vulnerabilities, and more.
              </p>
            </div>
          )}

          {messages.map((msg, i) => (
            <div
              key={i}
              className={classNames(
                "flex gap-2.5 animate-fade-in",
                msg.role === "user" ? "flex-row-reverse" : "flex-row"
              )}
            >
              {msg.role === "assistant" && (
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg skeu-bezel">
                  <Bot className="h-4 w-4 text-cyber-400" />
                </div>
              )}
              <div
                className={classNames(
                  "rounded-lg px-3 py-2 text-sm leading-relaxed max-w-[85%]",
                  msg.role === "user"
                    ? "bg-cyber-500/15 text-ink-100 border border-cyber-500/20"
                    : "skeu-bezel text-ink-200"
                )}
              >
                {msg.role === "assistant" ? (
                  <Markdown content={msg.content} />
                ) : (
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex gap-2.5 animate-fade-in">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg skeu-bezel">
                <Bot className="h-4 w-4 text-cyber-400" />
              </div>
              <div className="rounded-lg px-3 py-2 skeu-bezel">
                <Loader2 className="h-4 w-4 animate-spin text-cyber-400" />
              </div>
            </div>
          )}

          {error && (
            <div className="flex gap-2.5 animate-fade-in">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-danger/30 bg-danger/10">
                <AlertCircle className="h-4 w-4 text-danger" />
              </div>
              <div className="rounded-lg px-3 py-2 border border-danger/30 bg-danger/10 text-sm text-danger">
                {error}
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <div className="border-t border-ink-700/40 p-3 skeu-assistant-bar">
          <div className="flex items-end gap-2">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                webSearch
                  ? "Ask anything — web search is on…"
                  : "Ask about vulnerabilities, exploitability, remediation..."
              }
              rows={1}
              className="flex-1 resize-none rounded-lg border border-ink-700/50 px-3 py-2 text-sm text-ink-100 placeholder:text-ink-400 transition-all duration-150 focus:border-cyber-500/50 focus-visible:outline-none max-h-32"
              style={{
                background: "linear-gradient(180deg, rgba(5,8,17,0.6) 0%, rgba(10,15,26,0.5) 100%)",
                boxShadow: "inset 0 2px 4px rgba(0,0,0,0.4), inset 0 -1px 0 rgba(255,255,255,0.02)",
              }}
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || loading}
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-ink-950 transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: "linear-gradient(180deg, #1cc4f0 0%, #08a9d8 50%, #0889b5 100%)",
                boxShadow: "inset 0 1px 0 0 rgba(255,255,255,0.3), inset 0 -2px 0 0 rgba(0,0,0,0.2), 0 2px 4px rgba(0,0,0,0.25)",
              }}
            >
              <Send className="h-4 w-4" />
            </button>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setWebSearch((v) => !v)}
              aria-pressed={webSearch}
              title="Search the live web with Firecrawl before answering"
              className={classNames(
                "flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-semibold transition-colors skeu-bezel",
                webSearch ? "text-cyber-300" : "text-ink-400 hover:text-ink-200",
              )}
            >
              {researching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
              Web search {webSearch ? "on" : "off"}
            </button>
            {sources.length > 0 && (
              <span className="text-[10px] text-ink-500">{sources.length} sources used</span>
            )}
          </div>
          {webSearch && sources.length > 0 && (
            <ul className="mt-1.5 space-y-0.5">
              {sources.slice(0, 5).map((s, i) => (
                <li key={s.url} className="truncate text-[10px] text-ink-500">
                  <a href={s.url} target="_blank" rel="noreferrer noopener" className="hover:text-cyber-300">
                    [{i + 1}] {s.title}
                  </a>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-1.5 text-[10px] text-ink-600 flex items-center gap-1">
            <span className="led text-cyber-500" style={{ width: 5, height: 5 }} />
            Context-aware: sees data from {currentPage.replace(/-/g, " ")} page
          </p>
        </div>
      </div>
    </div>
  );
}

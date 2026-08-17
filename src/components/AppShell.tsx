import type { ReactNode } from "react";
import {
  LayoutDashboard,
  ScanSearch,
  ShieldAlert,
  Crosshair,
  Network,
  Package,
  Cpu,
  GitBranch,
  Globe,
  GitCompareArrows,
  Wrench,
  FileText,
  Settings,
  ShieldCheck,
  LogOut,
  Menu,
  X,
  Bot,
  Radio,
  KeyRound,
  Plug,
  FolderSearch,
  Bug,
  Sun,
  Moon,
} from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { classNames } from "@/lib/utils";
import { useTheme } from "@/lib/theme";
import { AIAssistant } from "@/components/AIAssistant";

export type PageId =
  | "dashboard"
  | "analyze"
  | "repo-scan"
  | "code-security"
  | "api-security"
  | "dast"
  | "secrets"
  | "exploitability"
  | "attack-paths"
  | "supply-chain"
  | "reverse-engineering"
  | "security-graph"
  | "threat-intel"
  | "kev"
  | "drift"
  | "remediation"
  | "reports"
  | "evidence"
  | "finding"
  | "ci-cd"
  | "settings";

interface NavItem {
  id: PageId;
  label: string;
  icon: ReactNode;
  group: string;
}

const NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard className="h-[18px] w-[18px]" />, group: "Overview" },
  { id: "analyze", label: "Analyze", icon: <ScanSearch className="h-[18px] w-[18px]" />, group: "Overview" },
  { id: "repo-scan", label: "Repository Scanner", icon: <FolderSearch className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "code-security", label: "Code Security", icon: <ShieldAlert className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "api-security", label: "API Security", icon: <Plug className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "dast", label: "DAST / Runtime", icon: <Radio className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "secrets", label: "Secret Detection", icon: <KeyRound className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "exploitability", label: "Exploitability", icon: <Crosshair className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "attack-paths", label: "Attack Paths", icon: <Network className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "supply-chain", label: "Supply Chain", icon: <Package className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "reverse-engineering", label: "Reverse Engineering", icon: <Cpu className="h-[18px] w-[18px]" />, group: "Analysis" },
  { id: "security-graph", label: "Security Graph", icon: <GitBranch className="h-[18px] w-[18px]" />, group: "Intelligence" },
  { id: "kev", label: "Known Exploited (KEV)", icon: <ShieldAlert className="h-[18px] w-[18px]" />, group: "Intelligence" },
  { id: "threat-intel", label: "Threat Intel", icon: <Globe className="h-[18px] w-[18px]" />, group: "Intelligence" },
  { id: "drift", label: "Drift", icon: <GitCompareArrows className="h-[18px] w-[18px]" />, group: "Intelligence" },
  { id: "remediation", label: "Remediation", icon: <Wrench className="h-[18px] w-[18px]" />, group: "Action" },
  { id: "evidence", label: "Evidence Center", icon: <FolderSearch className="h-[18px] w-[18px]" />, group: "Action" },
  { id: "finding", label: "Finding Details", icon: <Bug className="h-[18px] w-[18px]" />, group: "Action" },
  { id: "ci-cd", label: "CI/CD Gate", icon: <GitBranch className="h-[18px] w-[18px]" />, group: "Action" },
  { id: "reports", label: "Reports", icon: <FileText className="h-[18px] w-[18px]" />, group: "Action" },
  { id: "settings", label: "Settings", icon: <Settings className="h-[18px] w-[18px]" />, group: "Action" },
];

export function AppShell({
  current,
  onNavigate,
  children,
}: {
  current: PageId;
  onNavigate: (page: PageId) => void;
  children: ReactNode;
}) {
  const { user, signOut } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [assistantOpen, setAssistantOpen] = useState(false);

  const groups = [...new Set(NAV.map((n) => n.group))];

  const sidebar = (
    <div className="flex h-full flex-col bg-brushed-metal">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg skeu-bezel">
          <ShieldCheck className="h-5 w-5 text-cyber-400" />
        </div>
        <div>
          <p className="text-sm font-bold text-ink-100 tracking-wide">AegisCode</p>
          <p className="text-[10px] text-ink-500 uppercase tracking-wider">Security Platform</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-2">
        {groups.map((group) => (
          <div key={group} className="mb-4">
            <p className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-wider text-ink-500">{group}</p>
            {NAV.filter((n) => n.group === group).map((item) => (
              <div
                key={item.id}
                onClick={() => {
                  onNavigate(item.id);
                  setMobileOpen(false);
                }}
                className={classNames("nav-item mb-0.5", current === item.id && "nav-item-active")}
              >
                {item.icon}
                <span>{item.label}</span>
              </div>
            ))}
          </div>
        ))}
      </nav>

      <div className="border-t border-ink-700/40 p-3">
        <div className="flex items-center gap-2.5 rounded-lg px-3 py-2 skeu-bezel">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-steel-500/20 text-sm font-semibold text-steel-300 border border-steel-500/20">
            {(user?.email ?? "U").charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-xs font-medium text-ink-200">{user?.email ?? "User"}</p>
            <p className="text-[10px] text-volt-400 flex items-center gap-1">
              <span className="led text-volt-400" style={{ width: 6, height: 6 }} />
              Authenticated
            </p>
          </div>
          <button
            onClick={signOut}
            className="text-ink-400 hover:text-danger transition-colors"
            title="Sign out"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex h-[100dvh] overflow-hidden">
      {/* Desktop sidebar */}
      <aside className="hidden lg:flex w-64 shrink-0 border-r border-ink-700/40 skeu-bezel">
        {sidebar}
      </aside>

      {/* Mobile sidebar */}
      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 z-40 flex">
          <div className="fixed inset-0 bg-ink-950/80 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <aside className="relative z-50 w-[17rem] max-w-[85vw] border-r border-ink-700/40 skeu-bezel animate-slide-in-right">
            <button
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-3 text-ink-400 hover:text-ink-100"
            >
              <X className="h-5 w-5" />
            </button>
            {sidebar}
          </aside>
        </div>
      )}

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-ink-700/40 px-3 sm:px-4 lg:px-6 skeu-assistant-bar">
          <div className="flex min-w-0 items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden shrink-0 rounded-md p-1.5 text-ink-300 transition-colors hover:text-ink-100"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex min-w-0 items-center gap-2">
              <span className="led shrink-0 text-volt-400 animate-led-pulse" style={{ width: 8, height: 8 }} />
              <span className="truncate text-xs font-medium text-ink-400">All systems operational</span>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2 sm:gap-3">
            <span className="hidden md:inline text-xs text-ink-500 font-mono">v3.7.12</span>
            <div className="hidden md:block h-6 w-px bg-ink-700/40" />
            <button
              onClick={toggleTheme}
              role="switch"
              aria-checked={theme === "light"}
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-ink-300 transition-all duration-200 skeu-bezel hover:text-cyber-300"
            >
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <button
              onClick={() => setAssistantOpen(true)}
              className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium text-cyber-300 transition-all duration-150 skeu-bezel hover:text-cyber-200"
              title="Open AI Assistant"
            >
              <Bot className="h-4 w-4" />
              <span className="hidden sm:inline">AI Assistant</span>
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto bg-grid">
          <div className="mx-auto w-full max-w-7xl px-3 py-5 sm:px-4 sm:py-6 lg:px-8 lg:py-8">{children}</div>
        </main>
      </div>

      {/* AI Assistant */}
      <AIAssistant
        open={assistantOpen}
        onClose={() => setAssistantOpen(false)}
        currentPage={current}
        onNavigate={onNavigate}
      />
    </div>
  );
}

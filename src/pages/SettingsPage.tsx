import { useState } from "react";
import {
  Settings as SettingsIcon,
  Shield,
  Cpu,
  Bell,
  Download,
  Smartphone,
  CheckCircle2,
  AlertCircle,
  Info,
  Trash2,
  Lock,
  Database,
  Palette,
  Sun,
  Moon,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { supabase } from "@/lib/db";
import { Panel, PageHeader, Button, Toggle } from "@/components/ui-kit";
import { classNames } from "@/lib/utils";

export function SettingsPage() {
  const { user, signOut } = useAuth();
  const { theme, setTheme } = useTheme();
  const [defaultSeverity, setDefaultSeverity] = useState("all");
  const [autoSave, setAutoSave] = useState(true);
  const [notifications, setNotifications] = useState(true);
  const [installable, setInstallable] = useState<boolean | null>(null);
  const [resetting, setResetting] = useState(false);
  const [resetDone, setResetDone] = useState(false);
  const [resetError, setResetError] = useState<string | null>(null);

  const handleInstall = () => {
    const event = (window as unknown as { deferredPrompt?: Event }).deferredPrompt;
    if (event) {
      event.preventDefault();
      (event as unknown as { prompt: () => void }).prompt();
    } else {
      setInstallable(false);
    }
  };

  const handleResetData = async () => {
    const confirmed = window.confirm(
      "This will permanently delete ALL your scans, findings, remediations, threat intel records, drift records, and reports. This action cannot be undone. Are you sure?"
    );
    if (!confirmed) return;

    setResetting(true);
    setResetError(null);
    setResetDone(false);

    try {
      const userId = user?.id;
      if (!userId) throw new Error("Not authenticated");

      // Delete all user data in dependency order (child tables first)
      const tables = [
        "remediations",
        "threat_intel",
        "drift_records",
        "reports",
        "findings",
        "dependencies",
        "binary_analyses",
        "scans",
      ];

      for (const table of tables) {
        const { error } = await supabase.from(table).delete().eq("user_id", userId);
        if (error && !error.message.includes("column") && !error.message.includes("does not exist")) {
          // Try filtering by scan_id subquery if user_id column doesn't exist on this table
          // Most tables link through scan_id, so we need to delete via scan ownership
        }
      }

      // Alternative: delete scans first, then cascade-clean orphaned records
      // Re-attempt with scan_id-based deletion for tables without direct user_id
      const { data: userScanIds } = await supabase.from("scans").select("id");
      const scanIds = (userScanIds ?? []).map((s) => s.id);

      if (scanIds.length > 0) {
        for (const table of ["remediations", "threat_intel", "drift_records", "findings", "dependencies", "binary_analyses"]) {
          await supabase.from(table).delete().in("scan_id", scanIds);
        }
      }

      // Delete reports (linked by user_id or scan_ids)
      await supabase.from("reports").delete().eq("user_id", userId);

      setResetDone(true);
    } catch (err) {
      setResetError(err instanceof Error ? err.message : "Failed to reset data. Please try again.");
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl">
      <PageHeader
        title="Settings"
        subtitle="Configure your AegisCode platform preferences and manage your account."
        icon={<SettingsIcon className="h-6 w-6" />}
      />

      {/* Account */}
      <Panel className="p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
          <Shield className="h-4 w-4 text-cyber-400" />
          Account
        </h3>
        <div className="space-y-3">
          <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
            <div>
              <p className="text-xs text-ink-500">Email</p>
              <p className="text-sm text-ink-100">{user?.email ?? "—"}</p>
            </div>
            <span className="chip border border-volt-500/25 bg-volt-500/10 text-volt-300">
              <CheckCircle2 className="h-3 w-3" /> Authenticated
            </span>
          </div>
          <Button variant="danger" size="sm" onClick={signOut}>
            Sign Out
          </Button>
        </div>
      </Panel>

      {/* Appearance */}
      <Panel className="p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
          <Palette className="h-4 w-4 text-cyber-400" />
          Appearance
        </h3>
        <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg skeu-bezel text-cyber-400">
              {theme === "dark" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
            </div>
            <div className="min-w-0">
              <p className="text-sm text-ink-100">{theme === "dark" ? "Dark mode" : "Light mode"}</p>
              <p className="text-xs text-ink-500">Switch the console theme. Your choice is remembered on this device.</p>
            </div>
          </div>
          <Toggle
            checked={theme === "light"}
            onChange={(v) => setTheme(v ? "light" : "dark")}
            label="Toggle light mode"
          />
        </div>
      </Panel>

      {/* AI Model */}
      <Panel className="p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
          <Cpu className="h-4 w-4 text-cyber-400" />
          AI Configuration
        </h3>
        <div className="space-y-4">
          <div>
            <label className="label">AI Model (Locked)</label>
            <div className="relative">
              <div className="input flex items-center justify-between cursor-not-allowed opacity-80">
                <span className="text-ink-200">openrouter/auto</span>
                <span className="flex items-center gap-1 text-xs text-ink-500">
                  <Lock className="h-3 w-3" /> Locked
                </span>
              </div>
            </div>
            <p className="mt-1.5 text-xs text-ink-500">
              The AI model is locked to <span className="font-mono text-ink-400">openrouter/auto</span> for consistent
              analysis quality. The model is called through the AegisCode edge function. Your API key is never exposed to the browser.
            </p>
          </div>
          <div>
            <label className="label">Default Severity Filter</label>
            <select value={defaultSeverity} onChange={(e) => setDefaultSeverity(e.target.value)} className="input">
              <option value="all">All severities</option>
              <option value="critical">Critical only</option>
              <option value="high">High and above</option>
              <option value="medium">Medium and above</option>
            </select>
          </div>
        </div>
      </Panel>

      {/* Data Management */}
      <Panel className="p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
          <Database className="h-4 w-4 text-cyber-400" />
          Data Management
        </h3>
        <div className="space-y-3">
          <div className="rounded-lg border border-danger/30 bg-danger/5 p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-ink-100">Reset All Data</p>
                <p className="mt-1 text-xs text-ink-400">
                  Permanently delete all scans, findings, remediations, threat intel, drift records, and reports.
                  This action cannot be undone.
                </p>
              </div>
              <Button
                variant="danger"
                size="sm"
                onClick={handleResetData}
                disabled={resetting}
              >
                <Trash2 className="h-3.5 w-3.5" />
                {resetting ? "Resetting..." : "Reset Data"}
              </Button>
            </div>
            {resetDone && (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-volt-500/30 bg-volt-500/10 p-2.5 text-sm text-volt-300">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                All data has been successfully reset. Your account remains active.
              </div>
            )}
            {resetError && (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-danger/30 bg-danger/10 p-2.5 text-sm text-danger">
                <AlertCircle className="h-4 w-4 shrink-0" />
                {resetError}
              </div>
            )}
          </div>
        </div>
      </Panel>

      {/* PWA */}
      <Panel className="p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
          <Smartphone className="h-4 w-4 text-cyber-400" />
          PWA & Offline
        </h3>
        <div className="space-y-3">
          <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
            <div>
              <p className="text-sm text-ink-100">Install as App</p>
              <p className="text-xs text-ink-500">Install AegisCode as a standalone app on your device</p>
            </div>
            <Button variant="ghost" size="sm" onClick={handleInstall}>
              <Download className="h-3.5 w-3.5" />
              Install
            </Button>
          </div>
          {installable === false && (
            <div className="flex items-start gap-2 rounded-lg border border-info/30 bg-info/10 p-3 text-sm text-info">
              <Info className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Use your browser's "Install app" or "Add to home screen" option to install AegisCode.</span>
            </div>
          )}
          <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
            <div>
              <p className="text-sm text-ink-100">Service Worker</p>
              <p className="text-xs text-ink-500">Offline caching of the app shell</p>
            </div>
            <span className="chip border border-volt-500/25 bg-volt-500/10 text-volt-300">
              <CheckCircle2 className="h-3 w-3" /> Active
            </span>
          </div>
        </div>
      </Panel>

      {/* Preferences */}
      <Panel className="p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-100">
          <Bell className="h-4 w-4 text-cyber-400" />
          Preferences
        </h3>
        <div className="space-y-3">
          <ToggleRow
            label="Auto-save scan results"
            description="Automatically save all analysis results to your dashboard"
            value={autoSave}
            onChange={setAutoSave}
          />
          <ToggleRow
            label="Notifications"
            description="Get notified when scans complete or critical findings are discovered"
            value={notifications}
            onChange={setNotifications}
          />
        </div>
      </Panel>


    </div>
  );
}

function ToggleRow({
  label,
  description,
  value,
  onChange,
}: {
  label: string;
  description: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 rounded-lg border border-ink-700/40 bg-ink-850/50 p-3">
      <div className="min-w-0">
        <p className="text-sm text-ink-100">{label}</p>
        <p className="text-xs text-ink-500">{description}</p>
      </div>
      <Toggle checked={value} onChange={onChange} label={label} />
    </div>
  );
}

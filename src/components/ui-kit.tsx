import type { ReactNode } from "react";
import { classNames } from "@/lib/utils";
import type { Severity, Classification, Exploitability, RiskLevel } from "@/lib/types";
import {
  severityColor,
  severityLabel,
  classificationColor,
  classificationLabel,
  exploitabilityColor,
  exploitabilityLabel,
  riskColor,
} from "@/lib/utils";

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={classNames("chip border", severityColor(severity), className)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severityLabel(severity)}
    </span>
  );
}

export function ClassificationTag({ classification, className }: { classification: Classification; className?: string }) {
  return (
    <span className={classNames("chip border", classificationColor(classification), className)}>
      {classificationLabel(classification)}
    </span>
  );
}

export function ExploitabilityBadge({ exploitability, className }: { exploitability: Exploitability; className?: string }) {
  return (
    <span className={classNames("chip border", exploitabilityColor(exploitability), className)}>
      {exploitabilityLabel(exploitability)}
    </span>
  );
}

export function RiskBadge({ risk, className }: { risk: RiskLevel; className?: string }) {
  return (
    <span className={classNames("chip border", riskColor(risk), className)}>
      {risk.charAt(0).toUpperCase() + risk.slice(1)}
    </span>
  );
}

export function CvssScore({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-ink-400 text-xs">N/A</span>;
  const color =
    score >= 9 ? "text-danger" : score >= 7 ? "text-orange-400" : score >= 4 ? "text-warning" : "text-volt-300";
  return <span className={classNames("font-mono font-semibold text-sm", color)}>{score.toFixed(1)}</span>;
}

export function EpssScore({ score, percentile }: { score: number | null; percentile: number | null }) {
  if (score === null || score === undefined) return <span className="text-ink-400 text-xs">N/A</span>;
  const pct = (score * 100).toFixed(2);
  const per = percentile ? (percentile * 100).toFixed(0) : "—";
  return (
    <span className="font-mono text-xs text-ink-300">
      {pct}% <span className="text-ink-500">/ {per}p</span>
    </span>
  );
}

export function KevBadge({ inKev }: { inKev: boolean }) {
  if (!inKev) return null;
  return (
    <span className="chip border text-danger bg-danger/15 border-danger/30 animate-pulse">
      CISA KEV
    </span>
  );
}

export function Panel({
  children,
  className,
  hover,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  hover?: boolean;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={classNames("panel", hover && "panel-hover cursor-pointer", className)}
    >
      {children}
    </div>
  );
}

export function StatCard({
  label,
  value,
  icon,
  accent = "default",
  sub,
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  accent?: "default" | "danger" | "warning" | "volt" | "cyber";
  sub?: string;
}) {
  const accentMap = {
    default: "text-ink-100",
    danger: "text-danger",
    warning: "text-warning",
    volt: "text-volt-300",
    cyber: "text-cyber-300",
  };
  return (
    <Panel className="p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="stat-label">{label}</p>
          <p className={classNames("mt-2 text-3xl font-bold tracking-tight font-mono", accentMap[accent])}>
            {value}
          </p>
          {sub && <p className="mt-1 text-xs text-ink-400">{sub}</p>}
        </div>
        {icon && (
          <div className="text-ink-400">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg skeu-bezel">
              {icon}
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center animate-fade-in">
      {icon && <div className="mb-4 text-ink-500">{icon}</div>}
      <h3 className="text-lg font-semibold text-ink-100">{title}</h3>
      {description && <p className="mt-1.5 max-w-sm text-sm text-ink-400">{description}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function LoadingSpinner({ className, size = 20 }: { className?: string; size?: number }) {
  return (
    <svg
      className={classNames("animate-spin", className)}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
      <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  className,
  disabled,
  type = "button",
  size = "md",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger";
  className?: string;
  disabled?: boolean;
  type?: "button" | "submit";
  size?: "sm" | "md" | "lg";
}) {
  const variantClass = {
    primary: "btn-primary",
    ghost: "btn-ghost",
    danger: "btn-danger",
  }[variant];
  const sizeClass = { sm: "px-3 py-1.5 text-xs", md: "", lg: "px-6 py-3 text-base" }[size];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={classNames(variantClass, sizeClass, className)}
    >
      {children}
    </button>
  );
}

export function Modal({
  open,
  onClose,
  title,
  children,
  maxWidth = "max-w-2xl",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  maxWidth?: string;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 pt-20">
      <div className="fixed inset-0 bg-ink-950/80 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <div className={classNames("panel relative z-10 w-full p-6 animate-slide-in-up", maxWidth)}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink-100">{title}</h2>
          <button onClick={onClose} className="text-ink-400 hover:text-ink-100 transition-colors text-xl leading-none">
            &times;
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
  icon,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        {icon && (
          <div className="text-cyber-400">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg skeu-bezel">
              {icon}
            </div>
          </div>
        )}
        <div>
          <h1 className="text-xl font-bold text-ink-100 sm:text-2xl">{title}</h1>
          {subtitle && <p className="mt-0.5 text-sm text-ink-400">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CodeBlock({ code, language, className }: { code: string; language?: string; className?: string }) {
  return (
    <pre
      className={classNames(
        "overflow-x-auto rounded-lg p-4 font-mono text-[13px] leading-relaxed text-ink-200 skeu-screen",
        className
      )}
    >
      {language && <div className="mb-2 text-[10px] uppercase tracking-wider text-ink-500">{language}</div>}
      <code>{code}</code>
    </pre>
  );
}

export function Toggle({
  checked,
  onChange,
  disabled,
  label,
  className,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label?: string;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={classNames("skeu-toggle", checked && "skeu-toggle-on", className)}
    >
      <span className="skeu-toggle-knob" />
    </button>
  );
}


export function LedDot({ color, size = 8 }: { color: string; size?: number }) {
  return (
    <span
      className={classNames("led animate-led-pulse", color)}
      style={{ width: `${size}px`, height: `${size}px` }}
    />
  );
}

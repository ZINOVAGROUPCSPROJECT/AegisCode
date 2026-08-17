import { useEffect, useMemo, useState } from "react";
import {
  ShieldAlert,
  Search,
  Loader2,
  AlertCircle,
  Database,
  Skull,
  Link2,
  CalendarClock,
} from "lucide-react";
import { supabase } from "@/lib/db";
import { loadKevCatalog, indexByCve, extractCves, kevExploitationSignal } from "@/lib/kev";
import type { KevCatalog, KevEntry } from "@/lib/kev";
import {
  Panel,
  PageHeader,
  Button,
  EmptyState,
  StatCard,
  KevBadge,
  LoadingSpinner,
} from "@/components/ui-kit";
import { classNames } from "@/lib/utils";

interface CorrelatedAsset {
  cve: string;
  entry: KevEntry;
  sources: string[];
}

export function KevPage() {
  const [catalog, setCatalog] = useState<KevCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [vendor, setVendor] = useState("all");
  const [ransomOnly, setRansomOnly] = useState(false);
  const [page, setPage] = useState(0);
  const [correlated, setCorrelated] = useState<CorrelatedAsset[]>([]);
  const [correlating, setCorrelating] = useState(false);

  const PAGE_SIZE = 25;

  useEffect(() => {
    loadKevCatalog()
      .then(setCatalog)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  const vendors = useMemo(() => {
    if (!catalog) return [];
    const counts = new Map<string, number>();
    for (const v of catalog.vulnerabilities) {
      counts.set(v.vendorProject, (counts.get(v.vendorProject) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 40)
      .map(([name, count]) => ({ name, count }));
  }, [catalog]);

  const filtered = useMemo(() => {
    if (!catalog) return [];
    const q = query.trim().toLowerCase();
    return catalog.vulnerabilities.filter((v) => {
      if (vendor !== "all" && v.vendorProject !== vendor) return false;
      if (ransomOnly && (v.knownRansomwareCampaignUse || "").toLowerCase() !== "known") return false;
      if (!q) return true;
      return (
        v.cveID.toLowerCase().includes(q) ||
        v.vendorProject.toLowerCase().includes(q) ||
        v.product.toLowerCase().includes(q) ||
        v.vulnerabilityName.toLowerCase().includes(q) ||
        v.shortDescription.toLowerCase().includes(q) ||
        v.cwes.some((c) => c.toLowerCase().includes(q))
      );
    });
  }, [catalog, query, vendor, ransomOnly]);

  useEffect(() => {
    setPage(0);
  }, [query, vendor, ransomOnly]);

  const visible = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
  const ransomCount = catalog
    ? catalog.vulnerabilities.filter(
        (v) => (v.knownRansomwareCampaignUse || "").toLowerCase() === "known",
      ).length
    : 0;

  const runCorrelation = async () => {
    if (!catalog) return;
    setCorrelating(true);
    setError(null);
    try {
      const index = indexByCve(catalog);
      const [{ data: findings }, { data: deps }, { data: intel }] = await Promise.all([
        supabase.from("findings").select("id, title, description, cwe").limit(200),
        supabase.from("dependencies").select("name, version, vulnerabilities").limit(200),
        supabase.from("threat_intel").select("cve, description").limit(200),
      ]);

      const hits = new Map<string, CorrelatedAsset>();
      const add = (cve: string, source: string) => {
        const entry = index.get(cve.toUpperCase());
        if (!entry) return;
        const existing = hits.get(entry.cveID);
        if (existing) {
          if (!existing.sources.includes(source)) existing.sources.push(source);
        } else {
          hits.set(entry.cveID, { cve: entry.cveID, entry, sources: [source] });
        }
      };

      for (const f of (findings as { title?: string; description?: string }[]) ?? []) {
        for (const cve of extractCves(`${f.title ?? ""} ${f.description ?? ""}`)) {
          add(cve, `Finding: ${f.title ?? "untitled"}`);
        }
      }
      for (const d of (deps as { name?: string; version?: string; vulnerabilities?: unknown }[]) ??
        []) {
        for (const cve of extractCves(JSON.stringify(d.vulnerabilities ?? ""))) {
          add(cve, `Dependency: ${d.name ?? "unknown"}@${d.version ?? "?"}`);
        }
      }
      for (const t of (intel as { cve?: string; description?: string }[]) ?? []) {
        if (t.cve) add(t.cve, "Threat intel record");
        for (const cve of extractCves(t.description ?? "")) add(cve, "Threat intel record");
      }

      setCorrelated(Array.from(hits.values()));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCorrelating(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <LoadingSpinner className="text-cyber-400" size={28} />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Known Exploited Vulnerabilities"
        subtitle={
          catalog
            ? `CISA KEV catalog ${catalog.catalogVersion} — ${catalog.count.toLocaleString()} CVEs confirmed exploited in the wild.`
            : "CISA KEV catalog"
        }
        icon={<ShieldAlert className="h-6 w-6" />}
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="KEV Entries"
          value={catalog?.count ?? 0}
          icon={<Database className="h-5 w-5" />}
          accent="cyber"
        />
        <StatCard
          label="Ransomware Linked"
          value={ransomCount}
          icon={<Skull className="h-5 w-5" />}
          accent="danger"
        />
        <StatCard
          label="Matches In Your Data"
          value={correlated.length}
          icon={<Link2 className="h-5 w-5" />}
          accent="warning"
        />
        <StatCard
          label="Filtered Results"
          value={filtered.length}
          icon={<Search className="h-5 w-5" />}
          accent="default"
        />
      </div>

      <Panel className="p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1">
            <label className="label">Search the catalog</label>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="CVE id, vendor, product, CWE or keyword…"
              className="input"
            />
          </div>
          <div className="sm:w-56">
            <label className="label">Vendor</label>
            <select value={vendor} onChange={(e) => setVendor(e.target.value)} className="input">
              <option value="all">All vendors</option>
              {vendors.map((v) => (
                <option key={v.name} value={v.name}>
                  {v.name} ({v.count})
                </option>
              ))}
            </select>
          </div>
          <label className="flex shrink-0 items-center gap-2 pb-2 text-xs text-ink-300">
            <input
              type="checkbox"
              checked={ransomOnly}
              onChange={(e) => setRansomOnly(e.target.checked)}
            />
            Ransomware only
          </label>
          <Button onClick={runCorrelation} disabled={correlating} className="shrink-0">
            {correlating ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Link2 className="h-4 w-4" />
            )}
            {correlating ? "Correlating…" : "Correlate with my assets"}
          </Button>
        </div>
        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </Panel>

      {correlated.length > 0 && (
        <Panel className="p-5 animate-fade-in">
          <h3 className="mb-3 text-sm font-semibold text-ink-100">
            CVE → Asset Correlation ({correlated.length})
          </h3>
          <div className="space-y-2">
            {correlated.map((c) => {
              const signal = kevExploitationSignal(c.entry);
              return (
                <div
                  key={c.cve}
                  className="rounded-lg border border-danger/30 bg-danger/5 p-3"
                >
                  <div className="mb-1 flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-ink-100">{c.cve}</span>
                    <KevBadge inKev />
                    <span className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] uppercase text-ink-400">
                      exploitation likelihood: {signal.label}
                    </span>
                    {signal.ransomware && (
                      <span className="chip border border-danger/40 bg-danger/10 text-[10px] uppercase text-danger">
                        ransomware
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-ink-400">{c.entry.vulnerabilityName}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {c.sources.map((s, i) => (
                      <span
                        key={i}
                        className="chip border border-cyber-500/25 bg-cyber-500/10 text-[10px] text-cyber-300"
                      >
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {visible.length === 0 ? (
        <Panel className="p-8">
          <EmptyState
            icon={<ShieldAlert className="h-12 w-12" />}
            title="No matching KEV entries"
            description="Adjust the search terms or vendor filter to explore the catalog."
          />
        </Panel>
      ) : (
        <Panel className="overflow-hidden">
          <div className="divide-y divide-ink-800/60">
            {visible.map((v) => {
              const signal = kevExploitationSignal(v);
              return (
                <div key={v.cveID} className="p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-ink-100">{v.cveID}</span>
                    <KevBadge inKev />
                    <span className="chip border border-ink-700/60 bg-ink-800/60 text-[10px] uppercase text-ink-400">
                      {v.vendorProject}
                    </span>
                    {signal.ransomware && (
                      <span className="chip border border-danger/40 bg-danger/10 text-[10px] uppercase text-danger">
                        ransomware
                      </span>
                    )}
                    {v.cwes.map((c) => (
                      <span
                        key={c}
                        className="chip border border-cyber-500/25 bg-cyber-500/10 text-[10px] text-cyber-300"
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                  <p className="mt-1 text-sm font-medium text-ink-200">{v.vulnerabilityName}</p>
                  <p className="mt-1 text-xs text-ink-400">{v.shortDescription}</p>
                  <p className="mt-2 text-xs text-ink-300">
                    <span className="font-semibold text-ink-200">Required action: </span>
                    {v.requiredAction}
                  </p>
                  <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-ink-500">
                    <span className="flex items-center gap-1">
                      <CalendarClock className="h-3 w-3" /> Added {v.dateAdded}
                    </span>
                    {v.dueDate && <span>Due {v.dueDate}</span>}
                    <span>Product: {v.product}</span>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex items-center justify-between gap-3 border-t border-ink-800/60 px-4 py-3">
            <span className="text-xs text-ink-500">
              {page * PAGE_SIZE + 1}–{Math.min(filtered.length, (page + 1) * PAGE_SIZE)} of{" "}
              {filtered.length}
            </span>
            <div className="flex gap-2">
              <Button
                variant="ghost"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                Previous
              </Button>
              <Button
                variant="ghost"
                onClick={() => setPage((p) => p + 1)}
                disabled={(page + 1) * PAGE_SIZE >= filtered.length}
                className={classNames((page + 1) * PAGE_SIZE >= filtered.length && "opacity-50")}
              >
                Next
              </Button>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

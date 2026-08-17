import { useEffect, useState } from "react";
import { FileText, Loader2, Download, Trash2, FileCode, BarChart3 } from "lucide-react";
import { supabase } from "@/lib/db";
import type { Scan, Report, Finding } from "@/lib/types";
import {
  Panel,
  PageHeader,
  Button,
  EmptyState,
  SeverityBadge,
  ExploitabilityBadge,
  StatCard,
} from "@/components/ui-kit";
import { classNames, timeAgo, downloadFile, formatDate } from "@/lib/utils";

export function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [generating, setGenerating] = useState(false);
  const [reportTitle, setReportTitle] = useState("");

  useEffect(() => {
    (async () => {
      const [{ data: s }, { data: r }, { data: f }] = await Promise.all([
        supabase.from("scans").select("*").order("created_at", { ascending: false }),
        supabase.from("reports").select("*").order("created_at", { ascending: false }),
        supabase.from("findings").select("*").order("created_at", { ascending: false }),
      ]);
      setScans(s ?? []);
      setReports(r ?? []);
      setFindings((f as Finding[]) ?? []);
      setLoading(false);
    })();
  }, []);

  const toggleScan = (id: string) => {
    setSelectedScans((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const generateReport = async () => {
    if (selectedScans.size === 0) return;
    setGenerating(true);
    try {
      const scanIds = Array.from(selectedScans);
      const selectedFindings = findings.filter((f) => scanIds.includes(f.scan_id));
      const summary = {
        scans: scanIds.length,
        findings: selectedFindings.length,
        critical: selectedFindings.filter((f) => f.severity === "critical").length,
        high: selectedFindings.filter((f) => f.severity === "high").length,
        exploitable: selectedFindings.filter((f) => f.exploitability === "exploitable").length,
      };
      const content = {
        scans: scans.filter((s) => scanIds.includes(s.id)),
        findings: selectedFindings.map((f) => ({
          title: f.title,
          severity: f.severity,
          cwe: f.cwe,
          cvss: f.cvss_score,
          exploitability: f.exploitability,
          status: f.status,
          location: f.location,
        })),
      };

      const { data } = await supabase
        .from("reports")
        .insert({
          title: reportTitle || `Report — ${formatDate(new Date().toISOString())}`,
          scan_ids: scanIds,
          summary,
          content,
        })
        .select()
        .single();

      if (data) {
        setReports((prev) => [data as Report, ...prev]);
        setSelectedScans(new Set());
        setReportTitle("");
        downloadFile(
          `aegiscode-report-${data.id.slice(0, 8)}.json`,
          JSON.stringify(content, null, 2)
        );
      }
    } finally {
      setGenerating(false);
    }
  };

  const downloadReport = (report: Report) => {
    downloadFile(`aegiscode-report-${report.id.slice(0, 8)}.json`, JSON.stringify(report.content, null, 2));
  };

  const deleteReport = async (id: string) => {
    await supabase.from("reports").delete().eq("id", id);
    setReports((prev) => prev.filter((r) => r.id !== id));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-cyber-400" />
      </div>
    );
  }

  const totalFindings = findings.length;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const exploitableCount = findings.filter((f) => f.exploitability === "exploitable").length;
  const verifiedCount = findings.filter((f) => f.status === "verified").length;

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Reports"
        subtitle="Compose and export evidence-driven security reports from your scans and findings."
        icon={<FileText className="h-6 w-6" />}
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Scans" value={scans.length} icon={<FileText className="h-5 w-5" />} accent="cyber" />
        <StatCard label="Total Findings" value={totalFindings} icon={<BarChart3 className="h-5 w-5" />} accent="default" />
        <StatCard label="Critical" value={criticalCount} icon={<FileText className="h-5 w-5" />} accent="danger" />
        <StatCard label="Verified Gone" value={verifiedCount} icon={<FileText className="h-5 w-5" />} accent="volt" />
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <Panel className="p-5">
            <h3 className="mb-3 text-sm font-semibold text-ink-100">Select Scans for Report</h3>
            {scans.length === 0 ? (
              <EmptyState
                icon={<FileText className="h-10 w-10" />}
                title="No scans available"
                description="Run scans first to generate reports."
              />
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {scans.map((scan) => {
                  const scanFindings = findings.filter((f) => f.scan_id === scan.id);
                  return (
                    <div
                      key={scan.id}
                      onClick={() => toggleScan(scan.id)}
                      className={classNames(
                        "flex items-center justify-between rounded-lg border p-3 cursor-pointer transition-colors",
                        selectedScans.has(scan.id)
                          ? "border-cyber-500/40 bg-cyber-500/10"
                          : "border-ink-700/40 bg-ink-850/50 hover:border-ink-600/60"
                      )}
                    >
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-ink-100">{scan.name}</p>
                        <p className="text-xs text-ink-500">
                          {scanFindings.length} findings · {timeAgo(scan.created_at)}
                        </p>
                      </div>
                      <div
                        className={classNames(
                          "h-5 w-5 rounded border flex items-center justify-center",
                          selectedScans.has(scan.id) ? "border-cyber-400 bg-cyber-500/20" : "border-ink-600"
                        )}
                      >
                        {selectedScans.has(scan.id) && <span className="text-cyber-300 text-xs">&#10003;</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>

        <div className="lg:col-span-2 space-y-4">
          <Panel className="p-5">
            <h3 className="mb-3 text-sm font-semibold text-ink-100">Generate Report</h3>
            <label className="label">Report Title</label>
            <input
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              placeholder="Q3 Security Report..."
              className="input mb-3"
            />
            <div className="mb-3 rounded-lg border border-ink-700/40 bg-ink-850/50 p-3 text-xs">
              <p className="text-ink-400">Selected: <span className="text-ink-200 font-mono">{selectedScans.size}</span> scans</p>
            </div>
            <Button onClick={generateReport} disabled={generating || selectedScans.size === 0} className="w-full">
              {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
              {generating ? "Generating..." : "Generate & Download"}
            </Button>
          </Panel>
        </div>
      </div>

      <div>
        <h3 className="mb-3 text-sm font-semibold text-ink-100">Saved Reports</h3>
        {reports.length === 0 ? (
          <Panel className="p-8">
            <EmptyState
              icon={<FileCode className="h-12 w-12" />}
              title="No Reports Yet"
              description="Select scans above and generate a report. It will be saved here and downloaded as JSON."
            />
          </Panel>
        ) : (
          <div className="space-y-2">
            {reports.map((report) => (
              <Panel key={report.id} className="p-4">
                <div className="flex items-center justify-between">
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-ink-100">{report.title}</p>
                    <p className="text-xs text-ink-500 mt-0.5">
                      {(report.summary as Record<string, number>)?.["scans"] ?? 0} scans ·
                      {" "}{(report.summary as Record<string, number>)?.["findings"] ?? 0} findings ·
                      {" "}{timeAgo(report.created_at)}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" onClick={() => downloadReport(report)}>
                      <Download className="h-3.5 w-3.5" />
                      Download
                    </Button>
                    <button
                      onClick={() => deleteReport(report.id)}
                      className="text-ink-500 hover:text-danger transition-colors p-1.5"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </Panel>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

import { useEffect, useState, useMemo } from "react";
import { GitBranch, Loader2, Shield, Package, Cpu, Crosshair, AlertCircle } from "lucide-react";
import { supabase } from "@/lib/db";
import type { Scan, Finding, Dependency } from "@/lib/types";
import { Panel, PageHeader, EmptyState, SeverityBadge } from "@/components/ui-kit";
import { classNames } from "@/lib/utils";

interface GraphNode {
  id: string;
  label: string;
  type: "scan" | "finding" | "dependency" | "binary" | "threat";
  x: number;
  y: number;
}
interface GraphEdge {
  source: string;
  target: string;
}

export function SecurityGraphPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [deps, setDeps] = useState<Dependency[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    (async () => {
      const [{ data: s }, { data: f }, { data: d }] = await Promise.all([
        supabase.from("scans").select("*").order("created_at", { ascending: false }).limit(20),
        supabase.from("findings").select("*").order("created_at", { ascending: false }).limit(50),
        supabase.from("dependencies").select("*").order("created_at", { ascending: false }).limit(30),
      ]);
      setScans(s ?? []);
      setFindings((f as Finding[]) ?? []);
      setDeps((d as Dependency[]) ?? []);
      setLoading(false);
    })();
  }, []);

  const { nodes, edges } = useMemo(() => {
    const n: GraphNode[] = [];
    const e: GraphEdge[] = [];

    const centerX = 400;
    const scanCount = scans.length;
    scans.forEach((scan, i) => {
      const angle = (i / Math.max(scanCount, 1)) * Math.PI * 2;
      const radius = 150;
      n.push({
        id: scan.id,
        label: scan.name.slice(0, 20),
        type: "scan",
        x: centerX + Math.cos(angle) * radius,
        y: 300 + Math.sin(angle) * radius,
      });
    });

    const findingsByScan = new Map<string, Finding[]>();
    findings.forEach((f) => {
      const arr = findingsByScan.get(f.scan_id) ?? [];
      arr.push(f);
      findingsByScan.set(f.scan_id, arr);
    });

    let fIdx = 0;
    scans.forEach((scan) => {
      const scanFindings = findingsByScan.get(scan.id) ?? [];
      const scanNode = n.find((nn) => nn.id === scan.id);
      if (!scanNode) return;
      scanFindings.slice(0, 5).forEach((f, j) => {
        const nodeId = `f-${f.id}`;
        const angle = (j / Math.max(scanFindings.length, 1)) * Math.PI * 2;
        const fx = scanNode.x + Math.cos(angle) * 120;
        const fy = scanNode.y + Math.sin(angle) * 120;
        n.push({ id: nodeId, label: f.title.slice(0, 18), type: "finding", x: fx, y: fy });
        e.push({ source: scan.id, target: nodeId });
        fIdx++;
      });
    });

    const depsByScan = new Map<string, Dependency[]>();
    deps.forEach((d) => {
      const arr = depsByScan.get(d.scan_id) ?? [];
      arr.push(d);
      depsByScan.set(d.scan_id, arr);
    });

    scans.forEach((scan) => {
      const scanDeps = depsByScan.get(scan.id) ?? [];
      const scanNode = n.find((nn) => nn.id === scan.id);
      if (!scanNode) return;
      scanDeps.slice(0, 4).forEach((d, j) => {
        const nodeId = `d-${d.id}`;
        const angle = Math.PI + (j / Math.max(scanDeps.length, 1)) * Math.PI;
        const dx = scanNode.x + Math.cos(angle) * 120;
        const dy = scanNode.y + Math.sin(angle) * 120;
        n.push({ id: nodeId, label: d.name.slice(0, 16), type: "dependency", x: dx, y: dy });
        e.push({ source: scan.id, target: nodeId });
      });
    });

    return { nodes: n, edges: e };
  }, [scans, findings, deps]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-cyber-400" />
      </div>
    );
  }

  const nodeColors: Record<string, string> = {
    scan: "#0889b5",
    finding: "#ef4444",
    dependency: "#3366ff",
    binary: "#f59e0b",
    threat: "#dc2626",
  };
  const nodeIcons: Record<string, typeof Shield> = {
    scan: Shield,
    finding: Crosshair,
    dependency: Package,
    binary: Cpu,
    threat: AlertCircle,
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Continuous Security Graph"
        subtitle="Connect applications, code, dependencies, binaries, vulnerabilities, runtime behavior, and attack paths in a unified graph."
        icon={<GitBranch className="h-6 w-6" />}
      />

      {nodes.length === 0 ? (
        <Panel className="p-8">
          <EmptyState
            icon={<GitBranch className="h-12 w-12" />}
            title="Graph is Empty"
            description="Run scans to populate the security graph. It connects your scans, findings, and dependencies into a visual relationship map."
          />
        </Panel>
      ) : (
        <div className="grid gap-6 lg:grid-cols-4">
          <Panel className="p-5 lg:col-span-3 overflow-hidden">
            <div className="overflow-x-auto">
              <svg width="100%" height="600" className="min-w-[800px] bg-ink-950/40 rounded-lg">
                {/* Edges */}
                {edges.map((edge, i) => {
                  const source = nodes.find((n) => n.id === edge.source);
                  const target = nodes.find((n) => n.id === edge.target);
                  if (!source || !target) return null;
                  return (
                    <line
                      key={i}
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke="#283449"
                      strokeWidth={1}
                      strokeOpacity={0.6}
                    />
                  );
                })}
                {/* Nodes */}
                {nodes.map((node) => (
                  <g
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer"
                  >
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={selectedNode?.id === node.id ? 22 : 16}
                      fill={nodeColors[node.type]}
                      fillOpacity={0.15}
                      stroke={nodeColors[node.type]}
                      strokeWidth={selectedNode?.id === node.id ? 2.5 : 1.5}
                      className="transition-all"
                    />
                    <text
                      x={node.x}
                      y={node.y + 4}
                      textAnchor="middle"
                      fill={nodeColors[node.type]}
                      fontSize="9"
                      fontFamily="monospace"
                    >
                      {node.type.charAt(0).toUpperCase()}
                    </text>
                    <text
                      x={node.x}
                      y={node.y + 32}
                      textAnchor="middle"
                      fill="#8a99b3"
                      fontSize="9"
                      fontFamily="monospace"
                    >
                      {node.label}
                    </text>
                  </g>
                ))}
              </svg>
            </div>
          </Panel>

          <div className="space-y-4">
            <Panel className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-ink-100">Graph Legend</h3>
              <div className="space-y-2">
                {Object.entries(nodeColors).map(([type, color]) => {
                  const Icon = nodeIcons[type] ?? nodeIcons["service"]!;
                  return (
                    <div key={type} className="flex items-center gap-2">
                      <div
                        className="h-3 w-3 rounded-full"
                        style={{ background: color, opacity: 0.3, border: `1px solid ${color}` }}
                      />
                      <Icon className="h-3.5 w-3.5" style={{ color }} />
                      <span className="text-xs text-ink-300 capitalize">{type}</span>
                    </div>
                  );
                })}
              </div>
            </Panel>

            <Panel className="p-5">
              <h3 className="mb-3 text-sm font-semibold text-ink-100">Graph Stats</h3>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-ink-400">Nodes</span>
                  <span className="font-mono text-ink-200">{nodes.length}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-ink-400">Edges</span>
                  <span className="font-mono text-ink-200">{edges.length}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-ink-400">Scans</span>
                  <span className="font-mono text-ink-200">{scans.length}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-ink-400">Findings</span>
                  <span className="font-mono text-ink-200">{findings.length}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-ink-400">Dependencies</span>
                  <span className="font-mono text-ink-200">{deps.length}</span>
                </div>
              </div>
            </Panel>

            {selectedNode && (
              <Panel className="p-5 animate-fade-in">
                <h3 className="mb-3 text-sm font-semibold text-ink-100">Selected Node</h3>
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-ink-500 text-xs">Type:</span>
                    <span className="ml-2 capitalize text-ink-200">{selectedNode.type}</span>
                  </div>
                  <div>
                    <span className="text-ink-500 text-xs">Label:</span>
                    <span className="ml-2 text-ink-200">{selectedNode.label}</span>
                  </div>
                  {selectedNode.type === "finding" && (
                    <SeverityBadge severity={findings.find((f) => `f-${f.id}` === selectedNode.id)?.severity ?? "info"} />
                  )}
                </div>
              </Panel>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

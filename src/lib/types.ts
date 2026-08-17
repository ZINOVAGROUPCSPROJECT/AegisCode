export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Classification = "observed" | "verified" | "inferred" | "unknown";
export type Exploitability =
  | "exploitable"
  | "reachable"
  | "theoretical"
  | "not-exploitable"
  | "unknown";
export type ScanType = "code" | "supply_chain" | "binary" | "drift" | "full";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type FindingStatus = "open" | "triaged" | "remediated" | "verified" | "ignored";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "none" | "unknown";
export type VerificationStatus = "pending" | "verifying" | "verified" | "failed" | "unknown";
export type AttackPathStatus = "theoretical" | "reachable" | "validated";
export type DriftType = "dependency" | "code" | "configuration" | "artifact" | "behavior";
export type IntelSource =
  | "nvd"
  | "osv"
  | "cisa-kev"
  | "epss"
  | "vendor"
  | "internal"
  | "custom";

export interface EvidenceItem {
  type?: string;
  snippet?: string;
  explanation?: string;
  classification?: Classification;
}

export interface EvidenceChainNode {
  step: number;
  node: string;
  node_type?: string;
  detail: string;
  classification?: Classification;
}

export interface AttackPath {
  id: string;
  name: string;
  status: AttackPathStatus;
  confidence: number;
  classification?: Classification;
  entry_point?: string;
  steps: AttackPathStep[] | string[];
  impact?: string;
  prerequisites?: string[];
}

export interface AttackPathStep {
  order: number;
  action: string;
  node: string;
  node_type?: string;
  classification?: Classification;
}

export interface DataFlowNode {
  step: number;
  point: string;
  detail: string;
}

export interface Verdict {
  exploitable_in_this_app?: boolean;
  confidence?: number;
  reasoning?: string;
  classification?: Classification;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description: string | null;
  severity: Severity;
  cwe: string | null;
  cwe_url: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  in_kev: boolean;
  location: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  evidence: EvidenceItem[];
  evidence_chain: EvidenceChainNode[];
  remediation: string | null;
  secure_fix: string | null;
  reachability: Classification;
  exploitability: Exploitability;
  exploit_confidence: number;
  attack_paths: AttackPath[];
  data_flow: DataFlowNode[];
  verdict: Verdict;
  verified_gone: boolean;
  status: FindingStatus;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  name: string;
  scan_type: ScanType;
  status: ScanStatus;
  language: string | null;
  input_hash: string | null;
  loc: number | null;
  summary: ScanSummary;
  model: string;
  created_at: string;
  updated_at: string;
}

export interface ScanSummary {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  language?: string;
  loc?: number;
  [key: string]: unknown;
}

export interface Dependency {
  id: string;
  scan_id: string;
  name: string;
  version: string | null;
  ecosystem: string | null;
  license: string | null;
  direct: boolean;
  risk_level: RiskLevel;
  vulnerabilities: DepVulnerability[];
  poisoning_indicators: string[];
  behavioral_fingerprint: Record<string, unknown>;
  blast_radius: Record<string, unknown>;
  sbom_entry: Record<string, unknown>;
  reachability: Classification;
  created_at: string;
}

export interface DepVulnerability {
  cve?: string;
  severity?: string;
  fixed_in?: string | null;
  description?: string;
}

export interface BinaryAnalysis {
  id: string;
  scan_id: string;
  binary_name: string;
  architecture: string | null;
  format: string | null;
  sha256: string | null;
  strings: BinaryStringEntry[];
  imports: BinaryImport[];
  functions: BinaryFunction[];
  suspicious_apis: SuspiciousApi[];
  behavior: Record<string, string[]>;
  behavioral_diff: Record<string, unknown>;
  integrity_mismatches: IntegrityMismatch[];
  summary: Record<string, unknown>;
  created_at: string;
}

export interface BinaryStringEntry {
  value: string;
  category?: string;
  risk?: string;
}

export interface BinaryImport {
  name: string;
  library?: string;
  risk?: string;
  note?: string;
}

export interface BinaryFunction {
  name: string;
  address?: string;
  risk?: string;
}

export interface SuspiciousApi {
  api: string;
  reason: string;
  risk?: string;
}

export interface IntegrityMismatch {
  type: string;
  description: string;
  severity?: string;
  classification?: Classification;
}

export interface ThreatIntelRecord {
  id: string;
  finding_id: string | null;
  cve: string | null;
  source: IntelSource;
  description: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  in_kev: boolean;
  kev_date: string | null;
  intel_references: IntelReference[];
  raw: Record<string, unknown>;
  created_at: string;
}

export interface IntelReference {
  url: string;
  source: string;
}

export interface DriftRecord {
  id: string;
  scan_id: string | null;
  drift_type: DriftType;
  description: string;
  severity: Severity;
  before_state: Record<string, unknown>;
  after_state: Record<string, unknown>;
  security_impact: string | null;
  created_at: string;
}

export interface Remediation {
  id: string;
  finding_id: string;
  fix_code: string | null;
  fix_description: string | null;
  verification_status: VerificationStatus;
  verification_result: Record<string, unknown>;
  model: string;
  created_at: string;
  updated_at: string;
}

export interface Report {
  id: string;
  title: string;
  scan_ids: string[];
  summary: Record<string, unknown>;
  content: Record<string, unknown>;
  format: "json" | "html" | "markdown";
  created_at: string;
}

// AI response types (from edge function)
export interface AICodeAnalysisResult {
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    language: string;
    loc: number;
  };
  findings: AIFinding[];
}

export interface AIFinding {
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  cwe_name?: string;
  cvss_score: number;
  cvss_vector?: string;
  location: string;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  evidence: EvidenceItem[];
  evidence_chain: EvidenceChainNode[];
  remediation: string;
  secure_fix: string;
  reachability: Classification;
  exploitability: Exploitability;
  exploit_confidence: number;
  attack_paths: AttackPath[];
  data_flow: DataFlowNode[];
  verdict: Verdict;
}

export interface AIExploitabilityResult {
  exploitability: Exploitability;
  confidence: number;
  reasoning: string;
  reachability_chain: { step: number; point: string; reachable: boolean; classification: Classification }[];
  conditions_required: string[];
  attack_surface: string;
  mitigations_present: string[];
  verdict: string;
  classification: Classification;
}

export interface AIAttackPathsResult {
  paths: AttackPath[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  label: string;
}

export interface AISupplyChainResult {
  sbom: { name: string; version: string; ecosystem: string; license: string; direct: boolean }[];
  dependencies: AIDependency[];
  summary: { total: number; critical: number; high: number; poisoning_risk: number };
}

export interface AIDependency {
  name: string;
  version: string;
  ecosystem: string;
  risk_level: RiskLevel;
  vulnerabilities: DepVulnerability[];
  poisoning_indicators: string[];
  behavioral_fingerprint: { network: string[]; filesystem: string[]; process: string[]; crypto: string[] };
  blast_radius: { scope: string; affected_components: string[]; data_exposure: string };
  reachability: Classification;
}

export interface AIBinaryResult {
  summary: { format: string; architecture: string; sha256: string; risk_level: string };
  strings: BinaryStringEntry[];
  imports: BinaryImport[];
  functions: BinaryFunction[];
  suspicious_apis: SuspiciousApi[];
  behavior: Record<string, string[]>;
  behavioral_diff: { summary: string; differences: string[] };
  integrity_mismatches: IntegrityMismatch[];
}

export interface AIThreatIntelResult {
  records: {
    cve: string;
    source: IntelSource;
    description: string;
    cvss_score: number;
    epss_score: number;
    epss_percentile: number;
    in_kev: boolean;
    kev_date: string | null;
    references: IntelReference[];
    classification: Classification;
  }[];
  fusion_summary: string;
}

export interface AIRemediationResult {
  fix_description: string;
  fix_code: string;
  changes: { file: string; change: string; reason: string }[];
  verification_steps: string[];
  residual_risk: string;
}

export interface AIVerificationResult {
  verification_status: VerificationStatus;
  original_issue: string;
  checks: { check: string; passed: boolean; detail: string; classification: Classification }[];
  residual_issues: string[];
  verdict: string;
  confidence: number;
}

export interface AIDriftResult {
  drift_records: {
    drift_type: DriftType;
    description: string;
    severity: Severity;
    security_impact: string;
    classification: Classification;
  }[];
  summary: string;
}

export interface AIInvestigationResult {
  investigation_summary: string;
  hypotheses: {
    hypothesis: string;
    supported_by: string[];
    contradicted_by: string[];
    confidence: number;
    classification: Classification;
  }[];
  correlations: { finding: string; correlated_with: string; relationship: string; strength: string }[];
  recommendations: string[];
  open_questions: string[];
}

export interface AIResponse<T> {
  ok: boolean;
  action: string;
  model: string;
  result: T;
  usage: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number } | null;
}

/* ============================================================
 * API Security, DAST, Secret Detection, CI/CD gate
 * ============================================================ */

export type ApiRiskCategory =
  | "broken_auth"
  | "idor"
  | "injection"
  | "ssrf"
  | "mass_assignment"
  | "rate_limit"
  | "data_exposure"
  | "other";

export type TestOutcome = "vulnerable" | "safe" | "inconclusive" | "unknown";
export type ProbeVerdict = "confirmed" | "refuted" | "inconclusive";
export type SecretValidity = "likely_live" | "likely_test" | "revoked" | "unknown";
export type GateStatus = "passed" | "blocked" | "warning";

export interface ApiParameter {
  name: string;
  location: "path" | "query" | "body" | "header";
  type?: string;
  user_controlled?: boolean;
}

export interface ApiRisk {
  category: ApiRiskCategory;
  severity: Severity;
  detail: string;
  classification?: Classification;
}

export interface ApiTest {
  category: string;
  name: string;
  outcome: TestOutcome;
  severity?: Severity | null;
  request_example?: string;
  expected?: string;
  observed?: string;
  classification?: Classification;
  remediation?: string;
}

export interface ApiEndpointResult {
  method: string;
  path: string;
  handler?: string | null;
  auth_required?: boolean;
  auth_mechanism?: string | null;
  exposure?: "public" | "authenticated" | "internal" | "unknown";
  parameters?: ApiParameter[];
  risks?: ApiRisk[];
  risk_level?: RiskLevel;
  notes?: string | null;
  tests?: ApiTest[];
}

export interface AIApiSecurityResult {
  summary: {
    total_endpoints: number;
    unauthenticated: number;
    high_risk: number;
    tested: number;
    failed_tests: number;
  };
  endpoints: ApiEndpointResult[];
}

export interface DastProbe {
  name: string;
  category: string;
  request: string;
  expected_signal: string;
  observed_signal: string;
  verdict: ProbeVerdict;
  classification?: Classification;
}

export interface DastFinding {
  title: string;
  severity: Severity;
  cwe?: string | null;
  confirmed_at_runtime: boolean;
  confidence?: number;
  evidence?: EvidenceItem[];
  reproduction?: string;
  impact?: string;
  remediation?: string;
}

export interface AIDastResult {
  summary: {
    target: string;
    probes_run: number;
    confirmed: number;
    refuted: number;
    inconclusive: number;
    risk: RiskLevel;
  };
  probes: DastProbe[];
  findings: DastFinding[];
  runtime_notes?: string;
}

export interface SecretResult {
  secret_type: string;
  provider?: string | null;
  severity: Severity;
  masked_value: string;
  location?: string;
  line_start?: number | null;
  entropy?: number | null;
  validity?: SecretValidity;
  classification?: Classification;
  impact?: string;
  remediation?: string;
  rotation_steps?: string[];
}

export interface AISecretScanResult {
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    verified_live: number;
  };
  secrets: SecretResult[];
}

export interface PrGateFinding {
  title: string;
  severity: Severity;
  cwe?: string | null;
  file_path?: string | null;
  line_start?: number | null;
  status: "introduced" | "resolved" | "pre_existing";
  exploitability?: Exploitability;
  evidence?: EvidenceItem[];
  remediation?: string;
  suggested_patch?: string | null;
}

export interface AIPrGateResult {
  summary: {
    files_changed: number;
    introduced: number;
    resolved: number;
    risk: RiskLevel;
  };
  gate_status: GateStatus;
  blocking_reasons: string[];
  findings: PrGateFinding[];
  review_comment?: string;
}

/* ============================================================
 * Aegis Risk Score
 * ============================================================ */

export interface AegisRiskFactor {
  label: string;
  weight: number;
  value: number;
  contribution: number;
  detail: string;
}

export interface AegisRiskScore {
  score: number;
  band: RiskLevel;
  factors: AegisRiskFactor[];
}

CREATE TABLE IF NOT EXISTS public.scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL DEFAULT 'Untitled scan',
  scan_type text NOT NULL CHECK (scan_type IN ('code','supply_chain','binary','drift','full')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','cancelled')),
  language text,
  input_hash text,
  loc int,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  model text NOT NULL DEFAULT 'google/gemini-3.5-flash',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scans TO authenticated;
GRANT ALL ON public.scans TO service_role;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_scans" ON public.scans FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_scans" ON public.scans FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_scans" ON public.scans FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_scans" ON public.scans FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  title text NOT NULL,
  description text,
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('critical','high','medium','low','info')),
  cwe text,
  cwe_url text,
  cvss_score numeric(3,1),
  cvss_vector text,
  epss_score numeric(5,4),
  epss_percentile numeric(5,4),
  in_kev boolean NOT NULL DEFAULT false,
  location text,
  file_path text,
  line_start int,
  line_end int,
  evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
  evidence_chain jsonb NOT NULL DEFAULT '[]'::jsonb,
  remediation text,
  secure_fix text,
  reachability text NOT NULL DEFAULT 'unknown' CHECK (reachability IN ('observed','verified','inferred','unknown')),
  exploitability text NOT NULL DEFAULT 'unknown' CHECK (exploitability IN ('exploitable','reachable','theoretical','not-exploitable','unknown')),
  exploit_confidence numeric(3,0) DEFAULT 0,
  attack_paths jsonb NOT NULL DEFAULT '[]'::jsonb,
  data_flow jsonb NOT NULL DEFAULT '[]'::jsonb,
  verdict jsonb NOT NULL DEFAULT '{}'::jsonb,
  verified_gone boolean DEFAULT false,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','triaged','remediated','verified','ignored')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.findings TO authenticated;
GRANT ALL ON public.findings TO service_role;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_findings" ON public.findings FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_findings" ON public.findings FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_findings" ON public.findings FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_findings" ON public.findings FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.dependencies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  version text,
  ecosystem text,
  license text,
  direct boolean NOT NULL DEFAULT true,
  risk_level text NOT NULL DEFAULT 'unknown' CHECK (risk_level IN ('critical','high','medium','low','none','unknown')),
  vulnerabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
  poisoning_indicators jsonb NOT NULL DEFAULT '[]'::jsonb,
  behavioral_fingerprint jsonb NOT NULL DEFAULT '{}'::jsonb,
  blast_radius jsonb NOT NULL DEFAULT '{}'::jsonb,
  sbom_entry jsonb NOT NULL DEFAULT '{}'::jsonb,
  reachability text NOT NULL DEFAULT 'unknown' CHECK (reachability IN ('observed','verified','inferred','unknown')),
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dependencies TO authenticated;
GRANT ALL ON public.dependencies TO service_role;
ALTER TABLE public.dependencies ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_dependencies" ON public.dependencies FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_dependencies" ON public.dependencies FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_dependencies" ON public.dependencies FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_dependencies" ON public.dependencies FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.binary_analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  binary_name text NOT NULL,
  architecture text,
  format text,
  sha256 text,
  strings jsonb NOT NULL DEFAULT '[]'::jsonb,
  imports jsonb NOT NULL DEFAULT '[]'::jsonb,
  functions jsonb NOT NULL DEFAULT '[]'::jsonb,
  suspicious_apis jsonb NOT NULL DEFAULT '[]'::jsonb,
  behavior jsonb NOT NULL DEFAULT '{}'::jsonb,
  behavioral_diff jsonb NOT NULL DEFAULT '{}'::jsonb,
  integrity_mismatches jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.binary_analyses TO authenticated;
GRANT ALL ON public.binary_analyses TO service_role;
ALTER TABLE public.binary_analyses ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_binary_analyses" ON public.binary_analyses FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_binary_analyses" ON public.binary_analyses FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_binary_analyses" ON public.binary_analyses FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_binary_analyses" ON public.binary_analyses FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.threat_intel (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  finding_id uuid REFERENCES public.findings(id) ON DELETE SET NULL,
  cve text,
  source text NOT NULL DEFAULT 'nvd' CHECK (source IN ('nvd','osv','cisa-kev','epss','vendor','internal','custom')),
  description text,
  cvss_score numeric(3,1),
  epss_score numeric(5,4),
  epss_percentile numeric(5,4),
  in_kev boolean NOT NULL DEFAULT false,
  kev_date date,
  intel_references jsonb NOT NULL DEFAULT '[]'::jsonb,
  raw jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.threat_intel TO authenticated;
GRANT ALL ON public.threat_intel TO service_role;
ALTER TABLE public.threat_intel ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_threat_intel" ON public.threat_intel FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_threat_intel" ON public.threat_intel FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_threat_intel" ON public.threat_intel FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_threat_intel" ON public.threat_intel FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.drift_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES public.scans(id) ON DELETE SET NULL,
  drift_type text NOT NULL CHECK (drift_type IN ('dependency','code','configuration','artifact','behavior')),
  description text NOT NULL,
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('critical','high','medium','low','info')),
  before_state jsonb NOT NULL DEFAULT '{}'::jsonb,
  after_state jsonb NOT NULL DEFAULT '{}'::jsonb,
  security_impact text,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.drift_records TO authenticated;
GRANT ALL ON public.drift_records TO service_role;
ALTER TABLE public.drift_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_drift_records" ON public.drift_records FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_drift_records" ON public.drift_records FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_drift_records" ON public.drift_records FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_drift_records" ON public.drift_records FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.remediations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  finding_id uuid NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
  fix_code text,
  fix_description text,
  verification_status text NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending','verifying','verified','failed','unknown')),
  verification_result jsonb NOT NULL DEFAULT '{}'::jsonb,
  model text NOT NULL DEFAULT 'google/gemini-3.5-flash',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.remediations TO authenticated;
GRANT ALL ON public.remediations TO service_role;
ALTER TABLE public.remediations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_remediations" ON public.remediations FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_remediations" ON public.remediations FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_remediations" ON public.remediations FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_remediations" ON public.remediations FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE IF NOT EXISTS public.reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  title text NOT NULL DEFAULT 'Untitled report',
  scan_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  content jsonb NOT NULL DEFAULT '{}'::jsonb,
  format text NOT NULL DEFAULT 'json' CHECK (format IN ('json','html','markdown')),
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.reports TO authenticated;
GRANT ALL ON public.reports TO service_role;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own_reports" ON public.reports FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_reports" ON public.reports FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_reports" ON public.reports FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_reports" ON public.reports FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS idx_scans_user_created ON public.scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON public.findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_user_severity ON public.findings(user_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON public.findings(status);
CREATE INDEX IF NOT EXISTS idx_dependencies_scan ON public.dependencies(scan_id);
CREATE INDEX IF NOT EXISTS idx_binary_analyses_scan ON public.binary_analyses(scan_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_finding ON public.threat_intel(finding_id);
CREATE INDEX IF NOT EXISTS idx_drift_records_user ON public.drift_records(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediations_finding ON public.remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_reports_user ON public.reports(user_id, created_at DESC);

CREATE OR REPLACE FUNCTION public.aegis_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_scans_updated ON public.scans;
CREATE TRIGGER trg_scans_updated BEFORE UPDATE ON public.scans
  FOR EACH ROW EXECUTE FUNCTION public.aegis_touch_updated_at();

DROP TRIGGER IF EXISTS trg_findings_updated ON public.findings;
CREATE TRIGGER trg_findings_updated BEFORE UPDATE ON public.findings
  FOR EACH ROW EXECUTE FUNCTION public.aegis_touch_updated_at();

DROP TRIGGER IF EXISTS trg_remediations_updated ON public.remediations;
CREATE TRIGGER trg_remediations_updated BEFORE UPDATE ON public.remediations
  FOR EACH ROW EXECUTE FUNCTION public.aegis_touch_updated_at();
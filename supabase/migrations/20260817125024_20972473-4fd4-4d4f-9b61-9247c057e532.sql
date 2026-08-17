-- AegisCode consolidated production schema

-- ============ roles ============
CREATE TYPE public.app_role AS ENUM ('admin','analyst','viewer');

CREATE TABLE public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text,
  display_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role public.app_role)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role)
$$;

CREATE POLICY "profiles_select_own" ON public.profiles FOR SELECT TO authenticated
  USING (auth.uid() = id OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "profiles_insert_own" ON public.profiles FOR INSERT TO authenticated WITH CHECK (auth.uid() = id);
CREATE POLICY "profiles_update_own" ON public.profiles FOR UPDATE TO authenticated
  USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

CREATE POLICY "user_roles_select_own" ON public.user_roles FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.profiles (id, email, display_name)
  VALUES (NEW.id, NEW.email, COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email,'@',1)))
  ON CONFLICT (id) DO NOTHING;
  INSERT INTO public.user_roles (user_id, role) VALUES (NEW.id, 'analyst')
  ON CONFLICT (user_id, role) DO NOTHING;
  RETURN NEW;
END;
$$;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

CREATE OR REPLACE FUNCTION public.aegis_touch_updated_at()
RETURNS trigger LANGUAGE plpgsql SET search_path = public AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END; $$;

CREATE TRIGGER trg_profiles_updated BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.aegis_touch_updated_at();

-- ============ core analysis ============
CREATE TABLE public.scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL DEFAULT 'Untitled scan',
  scan_type text NOT NULL CHECK (scan_type IN ('code','supply_chain','binary','drift','full')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','cancelled')),
  language text,
  input_hash text,
  loc int,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  model text NOT NULL DEFAULT 'google/gemini-3.6-flash',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.findings (
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
  aegis_risk_score numeric,
  aegis_risk_factors jsonb,
  verified_gone boolean DEFAULT false,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','triaged','remediated','verified','ignored')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.dependencies (
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

CREATE TABLE public.binary_analyses (
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

CREATE TABLE public.threat_intel (
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

CREATE TABLE public.drift_records (
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

CREATE TABLE public.remediations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  finding_id uuid NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
  fix_code text,
  fix_description text,
  verification_status text NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending','verifying','verified','failed','unknown')),
  verification_result jsonb NOT NULL DEFAULT '{}'::jsonb,
  model text NOT NULL DEFAULT 'google/gemini-3.6-flash',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  title text NOT NULL DEFAULT 'Untitled report',
  scan_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  content jsonb NOT NULL DEFAULT '{}'::jsonb,
  format text NOT NULL DEFAULT 'json' CHECK (format IN ('json','html','markdown')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ============ api security / dast / secrets / ci ============
CREATE TABLE public.api_endpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES public.scans(id) ON DELETE SET NULL,
  method text NOT NULL DEFAULT 'GET',
  path text NOT NULL,
  handler text,
  auth_required boolean NOT NULL DEFAULT false,
  auth_mechanism text,
  exposure text NOT NULL DEFAULT 'unknown',
  parameters jsonb NOT NULL DEFAULT '[]'::jsonb,
  risks jsonb NOT NULL DEFAULT '[]'::jsonb,
  risk_level text NOT NULL DEFAULT 'unknown',
  notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.api_tests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  endpoint_id uuid REFERENCES public.api_endpoints(id) ON DELETE CASCADE,
  category text NOT NULL,
  name text NOT NULL,
  outcome text NOT NULL DEFAULT 'unknown',
  severity text,
  request_example text,
  expected text,
  observed text,
  classification text NOT NULL DEFAULT 'inferred',
  remediation text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.dast_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  target_url text NOT NULL,
  target_description text,
  status text NOT NULL DEFAULT 'completed',
  probes jsonb NOT NULL DEFAULT '[]'::jsonb,
  findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb,
  runtime_notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.secret_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES public.scans(id) ON DELETE SET NULL,
  secret_type text NOT NULL,
  provider text,
  severity text NOT NULL DEFAULT 'high',
  masked_value text,
  location text,
  line_start integer,
  entropy numeric,
  validity text NOT NULL DEFAULT 'unknown',
  classification text NOT NULL DEFAULT 'observed',
  impact text,
  remediation text,
  rotation_steps jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'open',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.ci_integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  provider text NOT NULL DEFAULT 'github',
  repository text NOT NULL,
  default_branch text NOT NULL DEFAULT 'main',
  scan_pull_requests boolean NOT NULL DEFAULT true,
  block_on_severity text NOT NULL DEFAULT 'high',
  block_on_exploitable boolean NOT NULL DEFAULT true,
  block_on_secrets boolean NOT NULL DEFAULT true,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, provider, repository)
);

CREATE TABLE public.pr_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  integration_id uuid REFERENCES public.ci_integrations(id) ON DELETE CASCADE,
  pr_number integer,
  title text NOT NULL,
  author text,
  branch text,
  diff_summary text,
  gate_status text NOT NULL DEFAULT 'passed',
  blocking_reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ============ repos / sbom ============
CREATE TABLE public.monitored_repos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  provider text NOT NULL DEFAULT 'github',
  owner text NOT NULL,
  repo text NOT NULL,
  branch text NOT NULL DEFAULT 'main',
  last_commit_sha text,
  last_scan_at timestamptz,
  auto_scan boolean NOT NULL DEFAULT true,
  block_on text NOT NULL DEFAULT 'critical',
  baseline jsonb NOT NULL DEFAULT '[]'::jsonb,
  seen_fingerprints jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.repo_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  repo_id uuid REFERENCES public.monitored_repos(id) ON DELETE CASCADE,
  repo_label text NOT NULL,
  commit_sha text,
  ref text,
  engine text NOT NULL DEFAULT 'sast',
  files_scanned integer NOT NULL DEFAULT 0,
  lines_scanned integer NOT NULL DEFAULT 0,
  findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  new_findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  fixed_findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  regressed_findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  gate_status text NOT NULL DEFAULT 'passed',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.sbom_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  source text,
  component_count integer NOT NULL DEFAULT 0,
  components jsonb NOT NULL DEFAULT '[]'::jsonb,
  vulnerabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ============ persistent AI assistant ============
CREATE TABLE public.ai_chat_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  title text NOT NULL DEFAULT 'New conversation',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.ai_chat_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL REFERENCES public.ai_chat_sessions(id) ON DELETE CASCADE,
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('user','assistant')),
  content text NOT NULL,
  page text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  action text NOT NULL,
  resource text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ============ grants, RLS, owner policies ============
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'scans','findings','dependencies','binary_analyses','threat_intel','drift_records',
    'remediations','reports','api_endpoints','api_tests','dast_runs','secret_findings',
    'ci_integrations','pr_scans','monitored_repos','repo_scans','sbom_reports',
    'ai_chat_sessions','ai_chat_messages'
  ] LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO authenticated', t);
    EXECUTE format('GRANT ALL ON public.%I TO service_role', t);
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR SELECT TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(), ''admin''))', t||'_select', t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id)', t||'_insert', t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)', t||'_update', t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR DELETE TO authenticated USING (auth.uid() = user_id)', t||'_delete', t);
  END LOOP;
END $$;

GRANT SELECT, INSERT ON public.audit_log TO authenticated;
GRANT ALL ON public.audit_log TO service_role;
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "audit_log_select" ON public.audit_log FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "audit_log_insert" ON public.audit_log FOR INSERT TO authenticated
  WITH CHECK (auth.uid() = user_id);

-- ============ updated_at triggers ============
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['scans','findings','remediations','api_endpoints','dast_runs','secret_findings','ci_integrations','monitored_repos','ai_chat_sessions'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.aegis_touch_updated_at()', 'trg_'||t||'_updated', t);
  END LOOP;
END $$;

-- ============ indexes ============
CREATE INDEX idx_scans_user_created ON public.scans(user_id, created_at DESC);
CREATE INDEX idx_findings_scan ON public.findings(scan_id);
CREATE INDEX idx_findings_user_severity ON public.findings(user_id, severity);
CREATE INDEX idx_findings_status ON public.findings(status);
CREATE INDEX idx_dependencies_scan ON public.dependencies(scan_id);
CREATE INDEX idx_binary_analyses_scan ON public.binary_analyses(scan_id);
CREATE INDEX idx_threat_intel_finding ON public.threat_intel(finding_id);
CREATE INDEX idx_drift_records_user ON public.drift_records(user_id, created_at DESC);
CREATE INDEX idx_remediations_finding ON public.remediations(finding_id);
CREATE INDEX idx_reports_user ON public.reports(user_id, created_at DESC);
CREATE INDEX idx_api_endpoints_user ON public.api_endpoints(user_id, created_at DESC);
CREATE INDEX idx_api_tests_endpoint ON public.api_tests(endpoint_id);
CREATE INDEX idx_dast_runs_user ON public.dast_runs(user_id, created_at DESC);
CREATE INDEX idx_secret_findings_user ON public.secret_findings(user_id, created_at DESC);
CREATE INDEX idx_pr_scans_user ON public.pr_scans(user_id, created_at DESC);
CREATE INDEX idx_monitored_repos_user ON public.monitored_repos(user_id, created_at DESC);
CREATE INDEX idx_repo_scans_user ON public.repo_scans(user_id, created_at DESC);
CREATE INDEX idx_sbom_reports_user ON public.sbom_reports(user_id, created_at DESC);
CREATE INDEX idx_ai_chat_sessions_user ON public.ai_chat_sessions(user_id, updated_at DESC);
CREATE INDEX idx_ai_chat_messages_session ON public.ai_chat_messages(session_id, created_at);
CREATE INDEX idx_audit_log_user ON public.audit_log(user_id, created_at DESC);
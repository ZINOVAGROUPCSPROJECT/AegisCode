-- API Security, DAST, Secret Detection and CI/CD surfaces for AegisCode

CREATE TABLE public.api_endpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.api_endpoints TO authenticated;
GRANT ALL ON public.api_endpoints TO service_role;
ALTER TABLE public.api_endpoints ENABLE ROW LEVEL SECURITY;

CREATE POLICY "api_endpoints_select_own" ON public.api_endpoints FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "api_endpoints_insert_own" ON public.api_endpoints FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "api_endpoints_update_own" ON public.api_endpoints FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "api_endpoints_delete_own" ON public.api_endpoints FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.api_tests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.api_tests TO authenticated;
GRANT ALL ON public.api_tests TO service_role;
ALTER TABLE public.api_tests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "api_tests_select_own" ON public.api_tests FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "api_tests_insert_own" ON public.api_tests FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "api_tests_update_own" ON public.api_tests FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "api_tests_delete_own" ON public.api_tests FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.dast_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.dast_runs TO authenticated;
GRANT ALL ON public.dast_runs TO service_role;
ALTER TABLE public.dast_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "dast_runs_select_own" ON public.dast_runs FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "dast_runs_insert_own" ON public.dast_runs FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "dast_runs_update_own" ON public.dast_runs FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "dast_runs_delete_own" ON public.dast_runs FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.secret_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.secret_findings TO authenticated;
GRANT ALL ON public.secret_findings TO service_role;
ALTER TABLE public.secret_findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "secret_findings_select_own" ON public.secret_findings FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "secret_findings_insert_own" ON public.secret_findings FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "secret_findings_update_own" ON public.secret_findings FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "secret_findings_delete_own" ON public.secret_findings FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.ci_integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.ci_integrations TO authenticated;
GRANT ALL ON public.ci_integrations TO service_role;
ALTER TABLE public.ci_integrations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "ci_integrations_select_own" ON public.ci_integrations FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "ci_integrations_insert_own" ON public.ci_integrations FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "ci_integrations_update_own" ON public.ci_integrations FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "ci_integrations_delete_own" ON public.ci_integrations FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.pr_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.pr_scans TO authenticated;
GRANT ALL ON public.pr_scans TO service_role;
ALTER TABLE public.pr_scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "pr_scans_select_own" ON public.pr_scans FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "pr_scans_insert_own" ON public.pr_scans FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "pr_scans_update_own" ON public.pr_scans FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "pr_scans_delete_own" ON public.pr_scans FOR DELETE TO authenticated USING (auth.uid() = user_id);

-- Aegis Risk Score persisted alongside findings so priority survives reloads
ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS aegis_risk_score numeric,
  ADD COLUMN IF NOT EXISTS aegis_risk_factors jsonb;

CREATE INDEX idx_api_endpoints_user ON public.api_endpoints(user_id, created_at DESC);
CREATE INDEX idx_api_tests_endpoint ON public.api_tests(endpoint_id);
CREATE INDEX idx_dast_runs_user ON public.dast_runs(user_id, created_at DESC);
CREATE INDEX idx_secret_findings_user ON public.secret_findings(user_id, created_at DESC);
CREATE INDEX idx_pr_scans_user ON public.pr_scans(user_id, created_at DESC);

CREATE OR REPLACE FUNCTION public.aegis_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER set_api_endpoints_updated_at BEFORE UPDATE ON public.api_endpoints
  FOR EACH ROW EXECUTE FUNCTION public.aegis_set_updated_at();
CREATE TRIGGER set_dast_runs_updated_at BEFORE UPDATE ON public.dast_runs
  FOR EACH ROW EXECUTE FUNCTION public.aegis_set_updated_at();
CREATE TRIGGER set_secret_findings_updated_at BEFORE UPDATE ON public.secret_findings
  FOR EACH ROW EXECUTE FUNCTION public.aegis_set_updated_at();
CREATE TRIGGER set_ci_integrations_updated_at BEFORE UPDATE ON public.ci_integrations
  FOR EACH ROW EXECUTE FUNCTION public.aegis_set_updated_at();

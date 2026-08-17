CREATE TABLE public.monitored_repos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.monitored_repos TO authenticated;
GRANT ALL ON public.monitored_repos TO service_role;
ALTER TABLE public.monitored_repos ENABLE ROW LEVEL SECURITY;

CREATE POLICY "monitored_repos_select_own" ON public.monitored_repos FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "monitored_repos_insert_own" ON public.monitored_repos FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "monitored_repos_update_own" ON public.monitored_repos FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "monitored_repos_delete_own" ON public.monitored_repos FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.repo_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
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

GRANT SELECT, INSERT, UPDATE, DELETE ON public.repo_scans TO authenticated;
GRANT ALL ON public.repo_scans TO service_role;
ALTER TABLE public.repo_scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "repo_scans_select_own" ON public.repo_scans FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "repo_scans_insert_own" ON public.repo_scans FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "repo_scans_update_own" ON public.repo_scans FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "repo_scans_delete_own" ON public.repo_scans FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.sbom_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid(),
  name text NOT NULL,
  source text,
  component_count integer NOT NULL DEFAULT 0,
  components jsonb NOT NULL DEFAULT '[]'::jsonb,
  vulnerabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.sbom_reports TO authenticated;
GRANT ALL ON public.sbom_reports TO service_role;
ALTER TABLE public.sbom_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "sbom_reports_select_own" ON public.sbom_reports FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "sbom_reports_insert_own" ON public.sbom_reports FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "sbom_reports_update_own" ON public.sbom_reports FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "sbom_reports_delete_own" ON public.sbom_reports FOR DELETE TO authenticated USING (auth.uid() = user_id);
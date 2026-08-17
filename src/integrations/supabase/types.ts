export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.15"
  }
  public: {
    Tables: {
      ai_chat_messages: {
        Row: {
          content: string
          created_at: string
          id: string
          page: string | null
          role: string
          session_id: string
          user_id: string
        }
        Insert: {
          content: string
          created_at?: string
          id?: string
          page?: string | null
          role: string
          session_id: string
          user_id?: string
        }
        Update: {
          content?: string
          created_at?: string
          id?: string
          page?: string | null
          role?: string
          session_id?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "ai_chat_messages_session_id_fkey"
            columns: ["session_id"]
            isOneToOne: false
            referencedRelation: "ai_chat_sessions"
            referencedColumns: ["id"]
          },
        ]
      }
      ai_chat_sessions: {
        Row: {
          created_at: string
          id: string
          title: string
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          title?: string
          updated_at?: string
          user_id?: string
        }
        Update: {
          created_at?: string
          id?: string
          title?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      api_endpoints: {
        Row: {
          auth_mechanism: string | null
          auth_required: boolean
          created_at: string
          exposure: string
          handler: string | null
          id: string
          method: string
          notes: string | null
          parameters: Json
          path: string
          risk_level: string
          risks: Json
          scan_id: string | null
          updated_at: string
          user_id: string
        }
        Insert: {
          auth_mechanism?: string | null
          auth_required?: boolean
          created_at?: string
          exposure?: string
          handler?: string | null
          id?: string
          method?: string
          notes?: string | null
          parameters?: Json
          path: string
          risk_level?: string
          risks?: Json
          scan_id?: string | null
          updated_at?: string
          user_id?: string
        }
        Update: {
          auth_mechanism?: string | null
          auth_required?: boolean
          created_at?: string
          exposure?: string
          handler?: string | null
          id?: string
          method?: string
          notes?: string | null
          parameters?: Json
          path?: string
          risk_level?: string
          risks?: Json
          scan_id?: string | null
          updated_at?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "api_endpoints_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      api_tests: {
        Row: {
          category: string
          classification: string
          created_at: string
          endpoint_id: string | null
          expected: string | null
          id: string
          name: string
          observed: string | null
          outcome: string
          remediation: string | null
          request_example: string | null
          severity: string | null
          user_id: string
        }
        Insert: {
          category: string
          classification?: string
          created_at?: string
          endpoint_id?: string | null
          expected?: string | null
          id?: string
          name: string
          observed?: string | null
          outcome?: string
          remediation?: string | null
          request_example?: string | null
          severity?: string | null
          user_id?: string
        }
        Update: {
          category?: string
          classification?: string
          created_at?: string
          endpoint_id?: string | null
          expected?: string | null
          id?: string
          name?: string
          observed?: string | null
          outcome?: string
          remediation?: string | null
          request_example?: string | null
          severity?: string | null
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "api_tests_endpoint_id_fkey"
            columns: ["endpoint_id"]
            isOneToOne: false
            referencedRelation: "api_endpoints"
            referencedColumns: ["id"]
          },
        ]
      }
      audit_log: {
        Row: {
          action: string
          created_at: string
          detail: Json
          id: string
          resource: string | null
          user_id: string
        }
        Insert: {
          action: string
          created_at?: string
          detail?: Json
          id?: string
          resource?: string | null
          user_id?: string
        }
        Update: {
          action?: string
          created_at?: string
          detail?: Json
          id?: string
          resource?: string | null
          user_id?: string
        }
        Relationships: []
      }
      binary_analyses: {
        Row: {
          architecture: string | null
          behavior: Json
          behavioral_diff: Json
          binary_name: string
          created_at: string
          format: string | null
          functions: Json
          id: string
          imports: Json
          integrity_mismatches: Json
          scan_id: string
          sha256: string | null
          strings: Json
          summary: Json
          suspicious_apis: Json
          user_id: string
        }
        Insert: {
          architecture?: string | null
          behavior?: Json
          behavioral_diff?: Json
          binary_name: string
          created_at?: string
          format?: string | null
          functions?: Json
          id?: string
          imports?: Json
          integrity_mismatches?: Json
          scan_id: string
          sha256?: string | null
          strings?: Json
          summary?: Json
          suspicious_apis?: Json
          user_id?: string
        }
        Update: {
          architecture?: string | null
          behavior?: Json
          behavioral_diff?: Json
          binary_name?: string
          created_at?: string
          format?: string | null
          functions?: Json
          id?: string
          imports?: Json
          integrity_mismatches?: Json
          scan_id?: string
          sha256?: string | null
          strings?: Json
          summary?: Json
          suspicious_apis?: Json
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "binary_analyses_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      ci_integrations: {
        Row: {
          block_on_exploitable: boolean
          block_on_secrets: boolean
          block_on_severity: string
          created_at: string
          default_branch: string
          enabled: boolean
          id: string
          provider: string
          repository: string
          scan_pull_requests: boolean
          updated_at: string
          user_id: string
        }
        Insert: {
          block_on_exploitable?: boolean
          block_on_secrets?: boolean
          block_on_severity?: string
          created_at?: string
          default_branch?: string
          enabled?: boolean
          id?: string
          provider?: string
          repository: string
          scan_pull_requests?: boolean
          updated_at?: string
          user_id?: string
        }
        Update: {
          block_on_exploitable?: boolean
          block_on_secrets?: boolean
          block_on_severity?: string
          created_at?: string
          default_branch?: string
          enabled?: boolean
          id?: string
          provider?: string
          repository?: string
          scan_pull_requests?: boolean
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      dast_runs: {
        Row: {
          created_at: string
          findings: Json
          id: string
          probes: Json
          runtime_notes: string | null
          status: string
          summary: Json | null
          target_description: string | null
          target_url: string
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          findings?: Json
          id?: string
          probes?: Json
          runtime_notes?: string | null
          status?: string
          summary?: Json | null
          target_description?: string | null
          target_url: string
          updated_at?: string
          user_id?: string
        }
        Update: {
          created_at?: string
          findings?: Json
          id?: string
          probes?: Json
          runtime_notes?: string | null
          status?: string
          summary?: Json | null
          target_description?: string | null
          target_url?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      dependencies: {
        Row: {
          behavioral_fingerprint: Json
          blast_radius: Json
          created_at: string
          direct: boolean
          ecosystem: string | null
          id: string
          license: string | null
          name: string
          poisoning_indicators: Json
          reachability: string
          risk_level: string
          sbom_entry: Json
          scan_id: string
          user_id: string
          version: string | null
          vulnerabilities: Json
        }
        Insert: {
          behavioral_fingerprint?: Json
          blast_radius?: Json
          created_at?: string
          direct?: boolean
          ecosystem?: string | null
          id?: string
          license?: string | null
          name: string
          poisoning_indicators?: Json
          reachability?: string
          risk_level?: string
          sbom_entry?: Json
          scan_id: string
          user_id?: string
          version?: string | null
          vulnerabilities?: Json
        }
        Update: {
          behavioral_fingerprint?: Json
          blast_radius?: Json
          created_at?: string
          direct?: boolean
          ecosystem?: string | null
          id?: string
          license?: string | null
          name?: string
          poisoning_indicators?: Json
          reachability?: string
          risk_level?: string
          sbom_entry?: Json
          scan_id?: string
          user_id?: string
          version?: string | null
          vulnerabilities?: Json
        }
        Relationships: [
          {
            foreignKeyName: "dependencies_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      drift_records: {
        Row: {
          after_state: Json
          before_state: Json
          created_at: string
          description: string
          drift_type: string
          id: string
          scan_id: string | null
          security_impact: string | null
          severity: string
          user_id: string
        }
        Insert: {
          after_state?: Json
          before_state?: Json
          created_at?: string
          description: string
          drift_type: string
          id?: string
          scan_id?: string | null
          security_impact?: string | null
          severity?: string
          user_id?: string
        }
        Update: {
          after_state?: Json
          before_state?: Json
          created_at?: string
          description?: string
          drift_type?: string
          id?: string
          scan_id?: string | null
          security_impact?: string | null
          severity?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "drift_records_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      findings: {
        Row: {
          aegis_risk_factors: Json | null
          aegis_risk_score: number | null
          attack_paths: Json
          created_at: string
          cvss_score: number | null
          cvss_vector: string | null
          cwe: string | null
          cwe_url: string | null
          data_flow: Json
          description: string | null
          epss_percentile: number | null
          epss_score: number | null
          evidence: Json
          evidence_chain: Json
          exploit_confidence: number | null
          exploitability: string
          file_path: string | null
          id: string
          in_kev: boolean
          line_end: number | null
          line_start: number | null
          location: string | null
          reachability: string
          remediation: string | null
          scan_id: string
          secure_fix: string | null
          severity: string
          status: string
          title: string
          updated_at: string
          user_id: string
          verdict: Json
          verified_gone: boolean | null
        }
        Insert: {
          aegis_risk_factors?: Json | null
          aegis_risk_score?: number | null
          attack_paths?: Json
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          cwe?: string | null
          cwe_url?: string | null
          data_flow?: Json
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          evidence?: Json
          evidence_chain?: Json
          exploit_confidence?: number | null
          exploitability?: string
          file_path?: string | null
          id?: string
          in_kev?: boolean
          line_end?: number | null
          line_start?: number | null
          location?: string | null
          reachability?: string
          remediation?: string | null
          scan_id: string
          secure_fix?: string | null
          severity?: string
          status?: string
          title: string
          updated_at?: string
          user_id?: string
          verdict?: Json
          verified_gone?: boolean | null
        }
        Update: {
          aegis_risk_factors?: Json | null
          aegis_risk_score?: number | null
          attack_paths?: Json
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          cwe?: string | null
          cwe_url?: string | null
          data_flow?: Json
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          evidence?: Json
          evidence_chain?: Json
          exploit_confidence?: number | null
          exploitability?: string
          file_path?: string | null
          id?: string
          in_kev?: boolean
          line_end?: number | null
          line_start?: number | null
          location?: string | null
          reachability?: string
          remediation?: string | null
          scan_id?: string
          secure_fix?: string | null
          severity?: string
          status?: string
          title?: string
          updated_at?: string
          user_id?: string
          verdict?: Json
          verified_gone?: boolean | null
        }
        Relationships: [
          {
            foreignKeyName: "findings_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      monitored_repos: {
        Row: {
          auto_scan: boolean
          baseline: Json
          block_on: string
          branch: string
          created_at: string
          id: string
          last_commit_sha: string | null
          last_scan_at: string | null
          owner: string
          provider: string
          repo: string
          seen_fingerprints: Json
          updated_at: string
          user_id: string
        }
        Insert: {
          auto_scan?: boolean
          baseline?: Json
          block_on?: string
          branch?: string
          created_at?: string
          id?: string
          last_commit_sha?: string | null
          last_scan_at?: string | null
          owner: string
          provider?: string
          repo: string
          seen_fingerprints?: Json
          updated_at?: string
          user_id?: string
        }
        Update: {
          auto_scan?: boolean
          baseline?: Json
          block_on?: string
          branch?: string
          created_at?: string
          id?: string
          last_commit_sha?: string | null
          last_scan_at?: string | null
          owner?: string
          provider?: string
          repo?: string
          seen_fingerprints?: Json
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      pr_scans: {
        Row: {
          author: string | null
          blocking_reasons: Json
          branch: string | null
          created_at: string
          diff_summary: string | null
          findings: Json
          gate_status: string
          id: string
          integration_id: string | null
          pr_number: number | null
          summary: Json | null
          title: string
          user_id: string
        }
        Insert: {
          author?: string | null
          blocking_reasons?: Json
          branch?: string | null
          created_at?: string
          diff_summary?: string | null
          findings?: Json
          gate_status?: string
          id?: string
          integration_id?: string | null
          pr_number?: number | null
          summary?: Json | null
          title: string
          user_id?: string
        }
        Update: {
          author?: string | null
          blocking_reasons?: Json
          branch?: string | null
          created_at?: string
          diff_summary?: string | null
          findings?: Json
          gate_status?: string
          id?: string
          integration_id?: string | null
          pr_number?: number | null
          summary?: Json | null
          title?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "pr_scans_integration_id_fkey"
            columns: ["integration_id"]
            isOneToOne: false
            referencedRelation: "ci_integrations"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string | null
          email: string | null
          id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id?: string
          updated_at?: string
        }
        Relationships: []
      }
      remediations: {
        Row: {
          created_at: string
          finding_id: string
          fix_code: string | null
          fix_description: string | null
          id: string
          model: string
          updated_at: string
          user_id: string
          verification_result: Json
          verification_status: string
        }
        Insert: {
          created_at?: string
          finding_id: string
          fix_code?: string | null
          fix_description?: string | null
          id?: string
          model?: string
          updated_at?: string
          user_id?: string
          verification_result?: Json
          verification_status?: string
        }
        Update: {
          created_at?: string
          finding_id?: string
          fix_code?: string | null
          fix_description?: string | null
          id?: string
          model?: string
          updated_at?: string
          user_id?: string
          verification_result?: Json
          verification_status?: string
        }
        Relationships: [
          {
            foreignKeyName: "remediations_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "findings"
            referencedColumns: ["id"]
          },
        ]
      }
      repo_scans: {
        Row: {
          commit_sha: string | null
          created_at: string
          engine: string
          files_scanned: number
          findings: Json
          fixed_findings: Json
          gate_status: string
          id: string
          lines_scanned: number
          new_findings: Json
          ref: string | null
          regressed_findings: Json
          repo_id: string | null
          repo_label: string
          summary: Json
          user_id: string
        }
        Insert: {
          commit_sha?: string | null
          created_at?: string
          engine?: string
          files_scanned?: number
          findings?: Json
          fixed_findings?: Json
          gate_status?: string
          id?: string
          lines_scanned?: number
          new_findings?: Json
          ref?: string | null
          regressed_findings?: Json
          repo_id?: string | null
          repo_label: string
          summary?: Json
          user_id?: string
        }
        Update: {
          commit_sha?: string | null
          created_at?: string
          engine?: string
          files_scanned?: number
          findings?: Json
          fixed_findings?: Json
          gate_status?: string
          id?: string
          lines_scanned?: number
          new_findings?: Json
          ref?: string | null
          regressed_findings?: Json
          repo_id?: string | null
          repo_label?: string
          summary?: Json
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "repo_scans_repo_id_fkey"
            columns: ["repo_id"]
            isOneToOne: false
            referencedRelation: "monitored_repos"
            referencedColumns: ["id"]
          },
        ]
      }
      reports: {
        Row: {
          content: Json
          created_at: string
          format: string
          id: string
          scan_ids: Json
          summary: Json
          title: string
          user_id: string
        }
        Insert: {
          content?: Json
          created_at?: string
          format?: string
          id?: string
          scan_ids?: Json
          summary?: Json
          title?: string
          user_id?: string
        }
        Update: {
          content?: Json
          created_at?: string
          format?: string
          id?: string
          scan_ids?: Json
          summary?: Json
          title?: string
          user_id?: string
        }
        Relationships: []
      }
      sbom_reports: {
        Row: {
          component_count: number
          components: Json
          created_at: string
          id: string
          name: string
          source: string | null
          summary: Json
          user_id: string
          vulnerabilities: Json
        }
        Insert: {
          component_count?: number
          components?: Json
          created_at?: string
          id?: string
          name: string
          source?: string | null
          summary?: Json
          user_id?: string
          vulnerabilities?: Json
        }
        Update: {
          component_count?: number
          components?: Json
          created_at?: string
          id?: string
          name?: string
          source?: string | null
          summary?: Json
          user_id?: string
          vulnerabilities?: Json
        }
        Relationships: []
      }
      scans: {
        Row: {
          created_at: string
          id: string
          input_hash: string | null
          language: string | null
          loc: number | null
          model: string
          name: string
          scan_type: string
          status: string
          summary: Json
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          input_hash?: string | null
          language?: string | null
          loc?: number | null
          model?: string
          name?: string
          scan_type: string
          status?: string
          summary?: Json
          updated_at?: string
          user_id?: string
        }
        Update: {
          created_at?: string
          id?: string
          input_hash?: string | null
          language?: string | null
          loc?: number | null
          model?: string
          name?: string
          scan_type?: string
          status?: string
          summary?: Json
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      secret_findings: {
        Row: {
          classification: string
          created_at: string
          entropy: number | null
          id: string
          impact: string | null
          line_start: number | null
          location: string | null
          masked_value: string | null
          provider: string | null
          remediation: string | null
          rotation_steps: Json
          scan_id: string | null
          secret_type: string
          severity: string
          status: string
          updated_at: string
          user_id: string
          validity: string
        }
        Insert: {
          classification?: string
          created_at?: string
          entropy?: number | null
          id?: string
          impact?: string | null
          line_start?: number | null
          location?: string | null
          masked_value?: string | null
          provider?: string | null
          remediation?: string | null
          rotation_steps?: Json
          scan_id?: string | null
          secret_type: string
          severity?: string
          status?: string
          updated_at?: string
          user_id?: string
          validity?: string
        }
        Update: {
          classification?: string
          created_at?: string
          entropy?: number | null
          id?: string
          impact?: string | null
          line_start?: number | null
          location?: string | null
          masked_value?: string | null
          provider?: string | null
          remediation?: string | null
          rotation_steps?: Json
          scan_id?: string | null
          secret_type?: string
          severity?: string
          status?: string
          updated_at?: string
          user_id?: string
          validity?: string
        }
        Relationships: [
          {
            foreignKeyName: "secret_findings_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      threat_intel: {
        Row: {
          created_at: string
          cve: string | null
          cvss_score: number | null
          description: string | null
          epss_percentile: number | null
          epss_score: number | null
          finding_id: string | null
          id: string
          in_kev: boolean
          intel_references: Json
          kev_date: string | null
          raw: Json
          source: string
          user_id: string
        }
        Insert: {
          created_at?: string
          cve?: string | null
          cvss_score?: number | null
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          finding_id?: string | null
          id?: string
          in_kev?: boolean
          intel_references?: Json
          kev_date?: string | null
          raw?: Json
          source?: string
          user_id?: string
        }
        Update: {
          created_at?: string
          cve?: string | null
          cvss_score?: number | null
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          finding_id?: string | null
          id?: string
          in_kev?: boolean
          intel_references?: Json
          kev_date?: string | null
          raw?: Json
          source?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "threat_intel_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "findings"
            referencedColumns: ["id"]
          },
        ]
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "analyst" | "viewer"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "analyst", "viewer"],
    },
  },
} as const

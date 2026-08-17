import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { AuthProvider, useAuth } from "@/lib/auth";
import { AppShell, type PageId } from "@/components/AppShell";
import { AuthScreen } from "@/components/AuthScreen";
import { LoadingSpinner } from "@/components/ui-kit";
import { DashboardPage } from "@/pages/DashboardPage";
import { AnalyzePage } from "@/pages/AnalyzePage";
import { RepoScanPage } from "@/pages/RepoScanPage";
import { CodeSecurityPage } from "@/pages/CodeSecurityPage";
import { ApiSecurityPage } from "@/pages/ApiSecurityPage";
import { DastPage } from "@/pages/DastPage";
import { SecretsPage } from "@/pages/SecretsPage";
import { EvidenceCenterPage } from "@/pages/EvidenceCenterPage";
import { FindingDetailPage } from "@/pages/FindingDetailPage";
import { CiCdPage } from "@/pages/CiCdPage";
import { ExploitabilityPage } from "@/pages/ExploitabilityPage";
import { AttackPathsPage } from "@/pages/AttackPathsPage";
import { SupplyChainPage } from "@/pages/SupplyChainPage";
import { ReverseEngineeringPage } from "@/pages/ReverseEngineeringPage";
import { SecurityGraphPage } from "@/pages/SecurityGraphPage";
import { ThreatIntelPage } from "@/pages/ThreatIntelPage";
import { KevPage } from "@/pages/KevPage";
import { DriftPage } from "@/pages/DriftPage";
import { RemediationPage } from "@/pages/RemediationPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { SettingsPage } from "@/pages/SettingsPage";

const title = "AegisCode — AI Application Security Platform";
const description =
  "AegisCode analyzes code for vulnerabilities, scores exploitability, maps attack paths, audits supply chains and verifies remediations with AI.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AegisCodeApp,
});

function AppContent() {
  const { session, loading } = useAuth();
  const [page, setPage] = useState<PageId>("dashboard");

  useEffect(() => {
    const hash = window.location.hash.slice(1) as PageId;
    if (hash) setPage(hash);
  }, []);

  useEffect(() => {
    window.location.hash = page;
  }, [page]);

  useEffect(() => {
    const onHashChange = () => {
      const hash = window.location.hash.slice(1) as PageId;
      if (hash) setPage(hash);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingSpinner className="text-cyber-400" size={32} />
      </div>
    );
  }

  if (!session) {
    return <AuthScreen />;
  }

  const renderPage = () => {
    switch (page) {
      case "dashboard":
        return <DashboardPage onNavigate={setPage} />;
      case "analyze":
        return <AnalyzePage onNavigate={setPage} />;
      case "repo-scan":
        return <RepoScanPage />;
      case "code-security":
        return <CodeSecurityPage onNavigate={setPage} />;
      case "api-security":
        return <ApiSecurityPage />;
      case "dast":
        return <DastPage />;
      case "secrets":
        return <SecretsPage />;
      case "evidence":
        return <EvidenceCenterPage onNavigate={setPage} />;
      case "finding":
        return <FindingDetailPage onNavigate={setPage} />;
      case "ci-cd":
        return <CiCdPage />;
      case "exploitability":
        return <ExploitabilityPage onNavigate={setPage} />;
      case "attack-paths":
        return <AttackPathsPage onNavigate={setPage} />;
      case "supply-chain":
        return <SupplyChainPage />;
      case "reverse-engineering":
        return <ReverseEngineeringPage />;
      case "security-graph":
        return <SecurityGraphPage />;
      case "kev":
        return <KevPage />;
      case "threat-intel":
        return <ThreatIntelPage />;
      case "drift":
        return <DriftPage />;
      case "remediation":
        return <RemediationPage onNavigate={setPage} />;
      case "reports":
        return <ReportsPage />;
      case "settings":
        return <SettingsPage />;
      default:
        return <DashboardPage onNavigate={setPage} />;
    }
  };

  return (
    <AppShell current={page} onNavigate={setPage}>
      {renderPage()}
    </AppShell>
  );
}

function AegisCodeApp() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

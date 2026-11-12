import { createBrowserRouter, Navigate } from "react-router-dom";
import AppShell from "@/components/ui/AppShell";
import ProtectedRoute from "@/auth/ProtectedRoute";

// Public Marketing & Entry Pages
import Landing from "@/pages/Landing";
import UserSelection from "@/pages/UserSelection";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import AnalystRegister from "@/pages/analyst/AnalystRegister";
import OrganizationCreate from "@/pages/organization/OrganizationCreate";
import Features from "@/pages/public/Features";
import HowItWorks from "@/pages/public/HowItWorks";
import Solutions from "@/pages/public/Solutions";
import Pricing from "@/pages/public/Pricing";
import About from "@/pages/public/About";
import { Terms, Privacy } from "@/pages/public/LegalPages";

// Individual Workspace Pages (Role: 'individual')
import PersonalDashboard from "@/pages/personal/PersonalDashboard";
import Devices from "@/pages/Devices";
import DeviceDetails from "@/pages/personal/DeviceDetails";
import EmailSecurity from "@/pages/personal/EmailSecurity";
import EmailAnalysis from "@/pages/personal/EmailAnalysis";
import LogMonitoring from "@/pages/personal/LogMonitoring";
import NetworkSecurity from "@/pages/personal/NetworkSecurity";
import Alerts from "@/pages/Alerts";
import AlertDetail from "@/pages/AlertDetail";
import AIAssistant from "@/pages/personal/AIAssistant";
import SecurityAnalysts from "@/pages/personal/SecurityAnalysts";
import PersonalMessages from "@/pages/personal/PersonalMessages";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";
import MyRoomsAndInvitations from "@/pages/personal/MyRoomsAndInvitations";

// Analyst Workspace Pages (Role: 'analyst')
import AnalystApplication from "@/pages/analyst/AnalystApplication";
import AnalystVerificationStep from "@/pages/analyst/AnalystVerificationStep";
import ApplicationStatus from "@/pages/analyst/ApplicationStatus";
import AnalystDashboard from "@/pages/analyst/AnalystDashboard";
import MyCases from "@/pages/analyst/MyCases";
import AvailableCases from "@/pages/analyst/AvailableCases";
import CaseDetail from "@/pages/CaseDetail";
import EvidenceLibrary from "@/pages/analyst/EvidenceLibrary";
import AIInvestigation from "@/pages/analyst/AIInvestigation";
import AnalystMessages from "@/pages/analyst/AnalystMessages";
import AnalystReports from "@/pages/analyst/AnalystReports";
import MyOfferings from "@/pages/analyst/MyOfferings";
import AnalystProfile from "@/pages/analyst/AnalystProfile";
import Earnings from "@/pages/analyst/Earnings";
import AnalystSettings from "@/pages/analyst/AnalystSettings";

// Organization Workspace Pages (Role: 'organizer', 'org_admin')
import OrganizationSetup from "@/pages/organization/OrganizationSetup";
import OrganizationDashboard from "@/pages/organization/OrganizationDashboard";
import OrganizationRooms from "@/pages/organization/OrganizationRooms";
import RoomWorkspace from "@/pages/organization/RoomWorkspace";
import Employees from "@/pages/organization/Employees";
import HireAnalysts from "@/pages/organization/HireAnalysts";
import OrganizationSettings from "@/pages/organization/OrganizationSettings";

const router = createBrowserRouter([
  // ── 1. PUBLIC MARKETING & ONBOARDING ROUTES ─────────────────────────────────
  { path: "/", Component: Landing },
  { path: "/features", Component: Features },
  { path: "/how-it-works", Component: HowItWorks },
  { path: "/solutions", Component: Solutions },
  { path: "/pricing", Component: Pricing },
  { path: "/about", Component: About },
  { path: "/terms", Component: Terms },
  { path: "/privacy", Component: Privacy },
  { path: "/select-account", Component: UserSelection },
  { path: "/login", Component: Login },
  { path: "/register", Component: Register },
  { path: "/analyst/register", Component: AnalystRegister },
  { path: "/organization/create", Component: OrganizationCreate },

  // Compatibility Redirects
  { path: "/individuals", element: <Navigate to="/register?type=individual" replace /> },
  { path: "/analysts", element: <Navigate to="/analyst/register" replace /> },
  { path: "/organizations", element: <Navigate to="/organization/create" replace /> },
  { path: "/analyst/login", element: <Navigate to="/login?portal=analyst" replace /> },
  { path: "/organization/login", element: <Navigate to="/login?portal=organizer" replace /> },

  // ── 2. INDIVIDUAL WORKSPACE (Role: 'individual') ──────────────────────────────
  {
    element: (
      <ProtectedRoute allowedRoles={["individual"]}>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      { path: "/personal/dashboard", Component: PersonalDashboard },
      { path: "/personal/devices", Component: Devices },
      { path: "/personal/devices/:deviceId", Component: DeviceDetails },
      { path: "/personal/email", Component: EmailSecurity },
      { path: "/personal/email/analysis", Component: EmailAnalysis },
      { path: "/personal/email/:analysisId", Component: EmailAnalysis },
      { path: "/personal/email-security", Component: EmailSecurity },
      { path: "/personal/email-security/analysis", Component: EmailAnalysis },
      { path: "/personal/logs", Component: LogMonitoring },
      { path: "/personal/network", Component: NetworkSecurity },
      { path: "/personal/alerts", Component: Alerts },
      { path: "/personal/alerts/:id", Component: AlertDetail },
      { path: "/personal/alerts/detail/:alertId", Component: AlertDetail },
      { path: "/personal/ai-assistant", Component: AIAssistant },
      { path: "/personal/analysts", Component: SecurityAnalysts },
      { path: "/personal/messages", Component: PersonalMessages },
      { path: "/personal/reports", Component: Reports },
      { path: "/personal/settings", Component: Settings },
      { path: "/personal/rooms", Component: MyRoomsAndInvitations },

      // Backward-compatible Top-Level Aliases
      { path: "/dashboard", element: <Navigate to="/personal/dashboard" replace /> },
      { path: "/devices", element: <Navigate to="/personal/devices" replace /> },
      { path: "/alerts", element: <Navigate to="/personal/alerts" replace /> },
      { path: "/alerts/:id", Component: AlertDetail },
      { path: "/reports", element: <Navigate to="/personal/reports" replace /> },
      { path: "/settings", element: <Navigate to="/personal/settings" replace /> },
    ],
  },

  // ── 3. ANALYST WORKSPACE (Role: 'analyst') ─────────────────────────────────────
  {
    element: (
      <ProtectedRoute allowedRoles={["analyst"]}>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      { path: "/analyst/application", Component: AnalystApplication },
      { path: "/analyst/verification", Component: AnalystVerificationStep },
      { path: "/analyst/status", Component: ApplicationStatus },
      { path: "/analyst/application-status", Component: ApplicationStatus },
      { path: "/analyst/dashboard", Component: AnalystDashboard },
      { path: "/analyst/cases", Component: MyCases },
      { path: "/analyst/cases/available", Component: AvailableCases },
      { path: "/analyst/available-cases", Component: AvailableCases },
      { path: "/analyst/cases/:id", Component: CaseDetail },
      { path: "/analyst/cases/detail/:caseId", Component: CaseDetail },
      { path: "/analyst/evidence", Component: EvidenceLibrary },
      { path: "/analyst/ai-investigation", Component: AIInvestigation },
      { path: "/analyst/messages", Component: AnalystMessages },
      { path: "/analyst/reports", Component: AnalystReports },
      { path: "/analyst/services", Component: MyOfferings },
      { path: "/analyst/my-offerings", Component: MyOfferings },
      { path: "/analyst/profile", Component: AnalystProfile },
      { path: "/analyst/earnings", Component: Earnings },
      { path: "/analyst/settings", Component: AnalystSettings },

      // Aliases
      { path: "/cases", element: <Navigate to="/analyst/cases" replace /> },
      { path: "/cases/:id", Component: CaseDetail },
    ],
  },

  // ── 4. ORGANIZATION WORKSPACE (Role: 'organizer', 'org_admin') ────────────────
  {
    element: (
      <ProtectedRoute allowedRoles={["organizer"]}>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      { path: "/organization/setup", Component: OrganizationSetup },
      { path: "/organization/onboarding", Component: OrganizationSetup },
      { path: "/organization/dashboard", Component: OrganizationDashboard },
      { path: "/organization/rooms", Component: OrganizationRooms },
      { path: "/organization/rooms/:roomId", Component: RoomWorkspace },
      { path: "/organization/employees", Component: Employees },
      { path: "/organization/analysts", Component: HireAnalysts },
      { path: "/organization/settings", Component: OrganizationSettings },
    ],
  },

  // ── 5. CATCH-ALL REDIRECT ─────────────────────────────────────────────────────
  {
    path: "*",
    element: <Navigate to="/" replace />,
  },
]);

export default router;

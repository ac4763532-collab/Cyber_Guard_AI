/**
 * CyberGuard AI — Landing (Home) Page
 * ============================================================================
 *
 * The public landing page of the multi-agent cybersecurity platform.
 * Reproduces the approved design with dark navy background, cyan/blue accents,
 * and all required sections in the specified order.
 *
 * Sections (in order):
 *  1. Header and Navigation
 *  2. Hero Section
 *  3. Three Security Experiences
 *  4. Eight AI Security Agents
 *  5. How It Works
 *  6. Platform Capabilities
 *  7. Trust and Security
 *  8. Frequently Asked Questions
 *  9. Final Call to Action
 * 10. Footer
 */

import { NavLink, useLocation } from "react-router-dom";
import {
  Shield,
  ShieldCheck,
  Microscope,
  AlertCircle,
  Server,
  Globe,
  LayoutDashboard,
  Save,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";

/* =============================================================
   NAVIGATION
   ============================================================= */

const navLinks = [
  { label: "Home", href: "/" },
  { label: "Features", href: "/features" },
  { label: "How It Works", href: "/how-it-works" },
  { label: "Solutions", href: "/solutions" },
  { label: "Pricing", href: "/pricing" },
  { label: "About", href: "/about" },
];

const authLinks = [
  { label: "Login", href: "/login", variant: "secondary" as const },
  { label: "Get Started", href: "/register", variant: "primary" as const },
];

/* =============================================================
   HERO
   ============================================================= */

const heroContent = (
  <div>
    <div className="eyebrow">INTELLIGENT SECURITY OPERATIONS</div>
    <h2>Intelligent Cybersecurity.<br/>One Unified Platform.</h2>
    <p>
      CyberGuard AI brings together intelligent threat detection, security
      monitoring, threat intelligence, and incident investigation to help
      individuals and organizations understand and respond to cyber threats.
    </p>
    <div className="flex gap-4 mt-6 flex-wrap">
      <Button variant="primary" size="lg">
        Get Started{" "}
        <span>/register</span>
      </Button>
      <Button variant="secondary" size="lg">
        Explore Platform{" "}
        <span>/features</span>
      </Button>
    </div>
  </div>
);

/* =============================================================
   THREE SECURITY EXPERIENCES
   ============================================================= */

const threeExperiences = (
  <div>
    <h3 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-10">
      Three Security Experiences
    </h3>
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
      {/* Personal Security */}
      <Card interactive
        className={cn("bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)]", "rounded-lg p-6")}
        onClick={() => window.location.href="/individuals"}
      >
        <CardHeader>
          <CardTitle>Personal Security</CardTitle>
        </CardHeader>
        <CardDescription>
          Protect your personal devices, monitor email activity, and analyze
          logs and network traffic for suspicious behavior. Get AI-powered
          security alerts and incidents delivered to your dashboard.
        </CardDescription>
        <CardContent>
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400">
            <Eye size={24} />
          </div>
          <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
            <li>Device monitoring</li>
            <li>Email, log and network analysis</li>
            <li>Threat alerts and incidents</li>
            <li>AI Security Assistant</li>
          </ul>
        </CardContent>
      </Card>

      {/* Security Analysts */}
      <Card interactive
        className={cn("bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)]", "rounded-lg p-6")}
        onClick={() => window.location.href="/analysts"}
      >
        <CardHeader>
          <CardTitle>Security Analysts</CardTitle>
        </CardHeader>
        <CardDescription>
          Professional analyst services for investigation and case management.
          Access verified analyst profiles, assign cases, and leverage AI
          investigation support for thorough security reviews.
        </CardDescription>
        <CardContent>
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
            <Shield size={24} />
          </div>
          <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
            <li>Professional profile</li>
            <li>Case investigation</li>
            <li>Evidence analysis</li>
            <li>AI investigation support</li>
            <li>Reports and services</li>
          </ul>
        </CardContent>
      </Card>

      {/* Organizations */}
      <Card interactive
        className={cn("bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)]", "rounded-lg p-6")}
        onClick={() => window.location.href="/organizations"}
      >
        <CardHeader>
          <CardTitle>Organizations</CardTitle>
        </CardHeader>
        <CardDescription>
          Cybersecurity management for companies. Create organizations, manage
          multiple rooms and departments, invite and manage analysts, and
          monitor device and data sources across the enterprise.
        </CardDescription>
        <CardContent>
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400">
            <Server size={24} />
          </div>
          <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
            <li>Create organization</li>
            <li>Multiple rooms and departments</li>
            <li>Multiple employee memberships</li>
            <li>Invite and manage analysts</li>
            <li>Device and data-source management</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  </div>
);

/* =============================================================
   EIGHT AI SECURITY AGENTS
   ============================================================= */

const eightAgents = (
  <div>
    <h3 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-8">
      Eight AI Security Agents
    </h3>
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <article className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Microscope size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">Email Analysis</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Analyze email threats, phishing attempts, and malicious content with
          AI-powered evidence-backed verdicts.
        </p>
      </article>

      <article className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <LayoutDashboard size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">Log Analysis</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Search and correlate log events from Windows, Linux, databases and
          web applications to detect anomalous activity.
        </p>
      </article>

      <article className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Globe size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">Network Analysis</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Review endpoint telemetry, connections, suspicious flows and sensor
          health across your authorized network.
        </p>
      </article>

      <article className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Microscope size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">AI Analyst</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Ask questions about your authorized security context and receive
          evidence-grounded explanations and summaries.
        </p>
      </article>

      <article className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Shield size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">Threat Intelligence</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Integrate external threat intelligence from sources like OpenPhoenix,
          AbuseIPDB, VirusTotal and NVD to enrich correlation and scoring.
        </p>
      </article>

      <article className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <AlertCircle size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">Incident Response</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Coordinate containment, eradication and recovery actions for active
          incidents with assigned analysts and evidence-backed playbooks.
        </p>
      </article>

      <article className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Save size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">Reporting</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Generate evidence-backed security reports and analytics for
          compliance, stakeholder review and audit trails.
        </p>
      </article>
    </div>
  </div>
);

/* =============================================================
   HOW IT WORKS
   ============================================================= */

const howItWorks = (
  <div>
    <h3 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-8">
      How It Works
    </h3>
    <div>
      <ol className="space-y-4 text-sm text-slate-600 dark:text-slate-400">
        <li>
          <span className="font-medium">Connect</span>
          <p>
            Integrate your data sources — endpoints, emails, logs, networks —
            through authorized collectors with agent credentials.
          </p>
        </li>
        <li>
          <span className="font-medium">Collect</span>
          <p>
            Security telemetry is normalized, enriched and stored in our
            centralized platform with full auditability.
          </p>
        </li>
        <li>
          <span className="font-medium">Detect</span>
          <p>
            Eight specialist AI agents run continuous correlation and rule
            matching to surface threats and anomalies.
          </p>
        </li>
        <li>
          <span className="font-medium">Correlate</span>
          <p>
            Cross-agent evidence is connected into attack chains, IOC clusters
            and incident timelines.
          </p>
        </li>
        <li>
          <span className="font-medium">Respond</span>
          <p>
            Assign incidents, coordinate analyst action, generate reports and
            close the loop with full audit trails.
          </p>
        </li>
      </ol>
    </div>
  </div>
);

/* =============================================================
   PLATFORM CAPABILITIES
   ============================================================= */

const platformCapabilities = (
  <div>
    <h3 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-8">
      Platform Capabilities
    </h3>
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Server size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">
          Centralized Security Monitoring
        </h4>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Unified dashboard across all endpoints, environments and user
          categories with real-time posture visibility.
        </p>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Shield size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">
          Multi-Agent Threat Detection
        </h4>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Eight specialized agents operate in parallel, each focusing on a
          distinct security domain with coordinated correlation.
        </p>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Globe size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">
          Threat Intelligence Integration
        </h4>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          OpenPhoenix, AbuseIPDB, VirusTotal and NVD feeds enriched into every
          alert, incident and case with automated IOC enrichment.
        </p>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <AlertCircle size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">
          Security Incident Management
        </h4>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Full incident lifecycle: creation, assignment, containment,
          eradication, recovery and resolution with auditability.
        </p>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Microscope size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">
          AI-Assisted Investigation
        </h4>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          AI Analyst provides evidence-grounded explanations, summaries and
          recommendations for any alert, incident or case.
        </p>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <div className="flex h-10 w-10 items-center justify-center rounded-md mb-3">
          <Save size={20} className="text-[var(--cyan)]" />
        </div>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">
          Security Reports and Analytics
        </h4>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Generate scheduled or ad-hoc reports with compliance-ready formats
          and export to PDF/CSV for stakeholder review.
        </p>
      </Card>
    </div>
  </div>
);

/* =============================================================
   TRUST AND SECURITY
   ============================================================= */

const trustAndSecurity = (
  <div>
    <h3 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-8">
      Trust and Security
    </h3>
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-3">
          Authorized Data Collection
        </h4>
        <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
          <li>All data collection is opt-in and requires explicit consent</li>
          <li>Collectors operate with minimal required permissions only</li>
          <li>Data is encrypted in transit (TLS 1.3) and at rest (AES-256)</li>
          <li>No personally identifiable data is stored beyond 30 days unless explicitly retained for investigation</li>
        </ul>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-3">
          Access Control
        </h4>
        <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
          <li>RBAC enforced by backend — role and organization permissions are never granted by frontend role selection</li>
          <li>JWT-based authentication with access/refresh token rotation</li>
          <li>Refresh tokens re-verify user status (PENDING_VERIFICATION → ACTIVE only after email verification)</li>
          <li>Account lockout after consecutive failed authentication attempts</li>
        </ul>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-3">
          Privacy First
        </h4>
        <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
          <li>Data minimization — only collect what is strictly required</li>
          <li>Privacy by design — privacy considerations built into every feature from the start</li>
          <li>GDPR-compliant data handling procedures</li>
          <li>Users can export or request deletion of their data at any time</li>
        </ul>
      </Card>

      <Card interactive className="bg-gradient-to-b from-[var(--panel)] to-[var(--panel2)] rounded-lg p-4" style={{ padding: "16px" }}>
        <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-3">
          Auditability
        </h4>
        <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
          <li>Complete audit logs of all administrative actions</li>
          <li>Immutable event chain from ingestion to incident closure</li>
          <li>All agent findings include MITRE technique mapping and confidence scores for traceability</li>
          <li>Audit reports exportable for compliance and governance reviews</li>
        </ul>
      </Card>
    </div>
  </div>
);

/* =============================================================
   FAQ
   ============================================================= */

const faq = (
  <div>
    <h3 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-8">
      Frequently Asked Questions
    </h3>
    <div>
      <details>
        <summary>What is CyberGuard AI?</summary>
        <div>
          CyberGuard AI is a multi-agent cybersecurity threat detection and
          correlation platform that brings together eight specialist AI agents
          to provide comprehensive coverage across email, log, network, threat
          intelligence, IOC correlation, incident response and reporting
          domains.
        </div>
      </details>

      <details>
        <summary>Who can use the platform?</summary>
        <div>
          The platform has three user categories: Normal User (individual
          protection), Security Analyst (professional investigation with
          verification required), and Company Admin (organization management).
          There is no Platform Admin or Super Admin category.
        </div>
      </details>

      <details>
        <summary>How does data collection work?</summary>
        <div>
          Data collection is performed by authorized collectors enrolled per
          workspace/organization. All collection is opt-in, requires explicit
          consent, and operates with minimal necessary permissions. Collected
          telemetry is normalized, encrypted and stored with full audit trails.
          Users can export or request deletion of their data at any time.
        </div>
      </details>

      <details>
        <summary>What are the eight AI security agents?</summary>
        <div>
          The eight agents are: 1) Email Analysis, 2) Log Analysis, 3) Network
          Analysis, 4) AI Analyst, 5) Threat Intelligence, 6) IOC Correlation,
          7) Incident Response, 8) Reporting. Each agent specializes in a
          distinct security domain with coordinated correlation across agents.
        </div>
      </details>

      <details>
        <summary>Is my data secure and private?</summary>
        <div>
          Yes. Data is encrypted in transit (TLS 1.3) and at rest (AES-256).
          Access is controlled via backend-enforced RBAC. Users retain ownership
          of their data and can export or request deletion at any time. The
          platform follows GDPR-compliant data handling procedures. No fake
          live threat counts or operational monitoring status is displayed.
        </div>
      </details>
    </div>
  </div>
);

/* =============================================================
   FINAL CTA
   ============================================================= */

const finalCTA = (
  <div>
    <h3 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-4">
      Take Control of Your Cybersecurity.
    </h3>
    <p className="text-slate-500 dark:text-slate-400 mb-6 max-w-2xl">
      Join thousands of individuals, analysts and organizations who trust
      CyberGuard AI to protect their digital environments.
    </p>
    <div className="flex gap-4 flex-wrap">
      <Button variant="primary" size="lg">
        Get Started{" "}
        <span>/register</span>
      </Button>
      <Button variant="secondary" size="lg">
        Explore Platform{" "}
        <span>/features</span>
      </Button>
    </div>
  </div>
);

/* =============================================================
   FOOTER
   ============================================================= */

const footerLinks = [
  { label: "Platform", links: ["/", "/features", "/how-it-works", "/pricing", "/about"] },
  { label: "Solutions", links: ["/individuals", "/analysts", "/organizations"] },
  { label: "Company", links: ["/careers", "/press", "/blog"] },
  { label: "Legal", links: ["/terms", "/privacy", "/compliance"] },
];

const footer = (
  <footer className="mt-16 pt-8 border-t border-slate-200 dark:border-slate-800">
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 mb-8">
      <div>
        <h4 className="font-bold text-slate-900 dark:text-slate-100 mb-4">CyberGuard AI</h4>
        <p className="text-slate-500 dark:text-slate-400 text-sm">
          Intelligent cybersecurity for individuals, analysts and organizations.
        </p>
      </div>
      <div>
        <h4 className="font-bold text-slate-900 dark:text-slate-100 mb-4">
          Platform
        </h4>
        <ul className="space-y-2 text-slate-500 dark:text-slate-400 text-sm">
          {footerLinks[0]?.links.map((l) => (
            <li key={l}>
              <NavLink to={l} className="hover:text-brand-600 transition-colors">
                {l}
              </NavLink>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h4 className="font-bold text-slate-900 dark:text-slate-100 mb-4">
          Solutions
        </h4>
        <ul className="space-y-2 text-slate-500 dark:text-slate-400 text-sm">
          {footerLinks[1]?.links.map((l) => (
            <li key={l}>
              <NavLink to={l} className="hover:text-brand-600 transition-colors">
                {l}
              </NavLink>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h4 className="font-bold text-slate-900 dark:text-slate-100 mb-4">
          Company
        </h4>
        <ul className="space-y-2 text-slate-500 dark:text-slate-400 text-sm">
          {footerLinks[2]?.links.map((l) => (
            <li key={l}>
              <NavLink to={l} className="hover:text-brand-600 transition-colors">
                {l}
              </NavLink>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h4 className="font-bold text-slate-900 dark:text-slate-100 mb-4">
          Legal
        </h4>
        <ul className="space-y-2 text-slate-500 dark:text-slate-400 text-sm">
          {footerLinks[3]?.links.map((l) => (
            <li key={l}>
              <NavLink to={l} className="hover:text-brand-600 transition-colors">
                {l}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 text-center text-xs text-slate-400 dark:text-slate-500">
          &copy; {new Date().getFullYear()} CyberGuard AI. All rights reserved.
        </div>
      </div>
    </div>
  </footer>
);

/* =============================================================
   MAIN COMPONENT
   ============================================================= */

export default function Landing() {
  useLocation();

  return (
    <main className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <div className="max-w-7xl mx-auto p-4 sm:p-6">
        {/* ── Header & Navigation ───────────────────────────────────── */}
        <header className="mb-12">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-6 w-6 text-brand-600" />
              <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-100">
                CyberGuard AI
              </span>
            </div>
            <nav>
              <ul className="flex gap-6 text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-slate-100 transition-colors font-medium">
                {navLinks.map((link) => (
                  <li key={link.label}>
                    <NavLink
                      to={link.href}
                      className={({ isActive }) =>
                        cn(
                          "relative after:content-[''] after:absolute after:left-0 after:-after:bottom-0 after:w-0 after:h-0.5 after:bg-brand-600 after:transition-colors after:duration-300",
                          isActive && "after:w-full"
                        )
                      }
                    >
                      {link.label}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </nav>
          </div>

          {/* ── Auth / Get Started ──────────────────────────────────── */}
          <div className="flex items-center gap-3">
            {authLinks.map((link) => (
              <Button
                key={link.label}
                variant={link.variant || "secondary"}
                size="sm"
              >
                {link.label}
              </Button>
            ))}
          </div>
        </header>

        {/* ── Hero ──────────────────────────────────────────────────── */}
        {heroContent}

        {/* ── Three Security Experiences ──────────────────────────── */}
        {threeExperiences}

        {/* ── Eight AI Security Agents ────────────────────────────── */}
        {eightAgents}

        {/* ── How It Works ──────────────────────────────────────────── */}
        {howItWorks}

        {/* ── Platform Capabilities ─────────────────────────────────── */}
        {platformCapabilities}

        {/* ── Trust and Security ────────────────────────────────────── */}
        {trustAndSecurity}

        {/* ── FAQ ─────────────────────────────────────────────────────── */}
        {faq}

        {/* ── Final CTA ───────────────────────────────────────────────── */}
        {finalCTA}

        {/* ── Footer ──────────────────────────────────────────────────── */}
        {footer}
      </div>
    </main>
  );
}
/**
 * CyberGuard AI — Automated Route & Navigation Verification Script
 * ============================================================================
 */

const fs = require("fs");
const path = require("path");

const FRONTEND_DIR = path.resolve(__dirname, "..");
const ROUTER_PATH = path.join(FRONTEND_DIR, "src", "app", "router.tsx");

console.log("================================================================================");
console.log("CYBERGUARD AI — AUTOMATED ROUTE & NAVIGATION AUDIT");
console.log("================================================================================");

const routerContent = fs.readFileSync(ROUTER_PATH, "utf8");

// Expected route specification from user requirement (Section 5)
const expectedRoutes = [
  // Public
  "/",
  "/select-account",
  "/login",
  "/register",
  "/features",
  "/how-it-works",
  "/solutions",
  "/pricing",
  "/about",
  "/terms",
  "/privacy",

  // Individual Workspace
  "/personal/dashboard",
  "/personal/devices",
  "/personal/devices/:deviceId",
  "/personal/email",
  "/personal/email/analysis",
  "/personal/logs",
  "/personal/network",
  "/personal/alerts",
  "/personal/alerts/:id",
  "/personal/ai-assistant",
  "/personal/analysts",
  "/personal/messages",
  "/personal/reports",
  "/personal/settings",
  "/personal/rooms",

  // Analyst Workspace
  "/analyst/register",
  "/analyst/application",
  "/analyst/verification",
  "/analyst/status",
  "/analyst/application-status",
  "/analyst/dashboard",
  "/analyst/cases",
  "/analyst/available-cases",
  "/analyst/cases/:id",
  "/analyst/evidence",
  "/analyst/ai-investigation",
  "/analyst/messages",
  "/analyst/reports",
  "/analyst/services",
  "/analyst/my-offerings",
  "/analyst/profile",
  "/analyst/earnings",
  "/analyst/settings",

  // Organization Workspace
  "/organization/create",
  "/organization/setup",
  "/organization/onboarding",
  "/organization/dashboard",
  "/organization/rooms",
  "/organization/rooms/:roomId",
  "/organization/employees",
  "/organization/analysts",
  "/organization/settings",
];

let allPassed = true;
let passCount = 0;
let failCount = 0;

console.log("\n1. Verifying Route Registrations in src/app/router.tsx:");
expectedRoutes.forEach((route) => {
  // Check if route string exists in routerContent
  const searchPattern = `path: "${route}"`;
  if (routerContent.includes(searchPattern)) {
    console.log(`  [PASS] ${route}`);
    passCount++;
  } else {
    console.log(`  [FAIL] Missing path: ${route}`);
    allPassed = false;
    failCount++;
  }
});

// Check Landing page for raw visible route text like <span>/register</span>
console.log("\n2. Checking Landing Page for Raw Route Text:");
const landingPath = path.join(FRONTEND_DIR, "src", "pages", "Landing.tsx");
const landingContent = fs.readFileSync(landingPath, "utf8");

if (landingContent.includes("<span>/register</span>") || landingContent.includes("<span>/features</span>")) {
  console.log("  [FAIL] Landing.tsx still contains raw route span text!");
  allPassed = false;
} else {
  console.log("  [PASS] Landing.tsx contains NO raw route span text.");
  passCount++;
}

// Check for dead window.location.href in Landing.tsx
if (landingContent.includes('window.location.href="/individuals"') || landingContent.includes('window.location.href="/analysts"')) {
  console.log("  [FAIL] Landing.tsx still contains window.location.href to invalid routes!");
  allPassed = false;
} else {
  console.log("  [PASS] Landing.tsx uses proper React Router navigation.");
  passCount++;
}

// Check UserSelection.tsx for invalid links
console.log("\n3. Checking UserSelection.tsx Navigation:");
const userSelectionPath = path.join(FRONTEND_DIR, "src", "pages", "UserSelection.tsx");
const userSelectionContent = fs.readFileSync(userSelectionPath, "utf8");

if (userSelectionContent.includes('href: "/personal/dashboard"')) {
  console.log("  [FAIL] UserSelection.tsx still points Individual to /personal/dashboard instead of /register!");
  allPassed = false;
} else {
  console.log("  [PASS] UserSelection.tsx points Individual to registration flow.");
  passCount++;
}

console.log("\n================================================================================");
console.log(`SUMMARY: ${passCount} PASSED, ${failCount} FAILED`);
console.log(`STATUS: ${allPassed ? "ALL AUDITS PASSED" : "AUDIT FAILED"}`);
console.log("================================================================================");

if (!allPassed) process.exit(1);

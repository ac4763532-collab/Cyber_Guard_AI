/**
 * CyberGuard AI — Frontend Utilities
 * ============================================================================
 * 
 * Shared helpers used across the entire frontend. Keeping these in one
 * place prevents duplicating logic (like class merging or date formatting)
 * in every component.
 * 
 * Exports:
 *   - `cn()` — Tailwind class merger (clsx + tailwind-merge)
 *   - Date formatting for alerts/findings (relative vs absolute)
 *   - Severity mapping (backend enums -> Tailwind color classes)
 *   - Status mapping (for badges)
 */

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { format, formatDistanceToNow } from "date-fns";


// ============================================================================
// TAILWIND CLASS MERGER
// ============================================================================

/**
 * Combines conditional classes and resolves Tailwind conflicts.
 * 
 * Example:
 *   cn("px-4 py-2", isActive && "bg-brand-500", "px-2")
 *   -> "py-2 bg-brand-500 px-2" (the px-2 overrides px-4)
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}


// ============================================================================
// DATE FORMATTING
// ============================================================================

/**
 * Formats an ISO date string to a readable absolute format.
 * e.g. "2026-11-07T14:23:45Z" -> "Nov 7, 2026, 2:23 PM"
 */
export function formatDate(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  try {
    const date = new Date(isoString);
    return format(date, "MMM d, yyyy, h:mm a");
  } catch {
    return "Invalid date";
  }
}

/**
 * Formats an ISO date string to a relative time (e.g. "5 minutes ago").
 * Used in alert lists where "just now" is more useful than a timestamp.
 */
export function formatRelativeTime(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  try {
    const date = new Date(isoString);
    return formatDistanceToNow(date, { addSuffix: true });
  } catch {
    return "Invalid date";
  }
}


// ============================================================================
// SEVERITY MAPPING
// ============================================================================
// Maps the backend's EventSeverity strings to our Tailwind theme.
// The `severity` color palette is defined in tailwind.config.ts.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/**
 * Returns the Tailwind classes for a severity badge.
 * Handles both light and dark modes automatically.
 */
export function getSeverityClasses(severity: string | undefined): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-severity-critical-bg text-severity-critical-text border-severity-critical-border dark:bg-severity-critical-darkBg dark:text-severity-critical-darkText dark:border-severity-critical-darkBorder";
    case "high":
      return "bg-severity-high-bg text-severity-high-text border-severity-high-border dark:bg-severity-high-darkBg dark:text-severity-high-darkText dark:border-severity-high-darkBorder";
    case "medium":
      return "bg-severity-medium-bg text-severity-medium-text border-severity-medium-border dark:bg-severity-medium-darkBg dark:text-severity-medium-darkText dark:border-severity-medium-darkBorder";
    case "low":
      return "bg-severity-low-bg text-severity-low-text border-severity-low-border dark:bg-severity-low-darkBg dark:text-severity-low-darkText dark:border-severity-low-darkBorder";
    case "info":
    default:
      return "bg-severity-info-bg text-severity-info-text border-severity-info-border dark:bg-severity-info-darkBg dark:text-severity-info-darkText dark:border-severity-info-darkBorder";
  }
}


// ============================================================================
// STATUS MAPPING (For Badges)
// ============================================================================

export type Status = 
  | "new" 
  | "acknowledged" 
  | "investigating" 
  | "resolved" 
  | "dismissed" 
  | "false_positive"
  | "open"
  | "in_progress"
  | "closed";

/**
 * Returns Tailwind classes for a status badge (gray, blue, green, red, etc.)
 */
export function getStatusClasses(status: string | undefined): string {
  switch (status?.toLowerCase()) {
    case "new":
    case "open":
      return "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800";
    case "acknowledged":
      return "bg-purple-100 text-purple-800 border-purple-200 dark:bg-purple-900/30 dark:text-purple-300 dark:border-purple-800";
    case "investigating":
    case "in_progress":
      return "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800";
    case "resolved":
    case "closed":
      return "bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800";
    case "dismissed":
    case "false_positive":
      return "bg-slate-100 text-slate-800 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700";
    default:
      return "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700";
  }
}
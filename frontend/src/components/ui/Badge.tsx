/**
 * CyberGuard AI — Badge Component
 * ============================================================================
 * 
 * Small visual indicators for severity, status, and tags.
 * 
 * Types:
 *   - Severity: "critical" | "high" | "medium" | "low" | "info"
 *     (uses the severity color palette from tailwind.config.ts)
 *   - Status: "new" | "investigating" | "resolved" | etc.
 *   - Custom: pass a raw Tailwind class string via `variant="custom"`
 * 
 * Features:
 *   - Automatic color mapping via utility functions
 *   - Optional status dot (colored circle)
 *   - Optional icon
 *   - Full dark mode support
 * 
 * Usage:
 *   <Badge severity="critical" />
 *   <Badge status="investigating" />
 *   <Badge severity="high" withDot />
 *   <Badge variant="outline" label="Windows" />
 */

import React from "react";
import { cn, getSeverityClasses, getStatusClasses } from "@/lib/utils";


// ============================================================================
// TYPES
// ============================================================================

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** Severity level — auto-colors the badge (mutually exclusive with `status`) */
  severity?: string;
  
  /** Status level — auto-colors the badge */
  status?: string;
  
  /** Optional label. If omitted, uses the value of `severity` or `status` as the text. */
  label?: string;
  
  /** Style variant — `severity` and `status` imply their own styles */
  variant?: "severity" | "status" | "outline" | "custom" | "default";
  
  /** If true, prepends a small colored dot before the text */
  withDot?: boolean;
  
  /** Optional icon (Lucide or any ReactNode) */
  icon?: React.ReactNode;
  
  /** For `variant="custom"`, the raw classes to apply */
  customClassName?: string;
}


// ============================================================================
// DOT COLORS (for withDot)
// ============================================================================

const severityDotColors: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-green-500",
  info: "bg-blue-500",
};

const statusDotColors: Record<string, string> = {
  new: "bg-blue-500",
  acknowledged: "bg-purple-500",
  investigating: "bg-amber-500",
  in_progress: "bg-amber-500",
  resolved: "bg-green-500",
  closed: "bg-green-500",
  dismissed: "bg-slate-400",
  false_positive: "bg-slate-400",
};


// ============================================================================
// COMPONENT
// ============================================================================

export function Badge({
  severity,
  status,
  label,
  variant,
  withDot = false,
  icon,
  customClassName,
  className,
  children,
  ...props
}: BadgeProps) {
  
  // ── Determine visual style ───────────────────────────────────────────
  let colorClasses = "";
  let dotClass = "";
  
  if (variant === "outline") {
    colorClasses = "border border-slate-300 text-slate-700 bg-transparent dark:border-slate-700 dark:text-slate-300";
  } else if (variant === "custom" || (!severity && !status)) {
    colorClasses = customClassName || "bg-slate-100 text-slate-800 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700";
  } else if (severity) {
    colorClasses = getSeverityClasses(severity);
    dotClass = severityDotColors[severity.toLowerCase()] || "bg-slate-400";
  } else if (status) {
    colorClasses = getStatusClasses(status);
    dotClass = statusDotColors[status.toLowerCase()] || "bg-slate-400";
  }

  // ── Determine label text ─────────────────────────────────────────────
  const displayText = children || label || severity || status || "";

  // ── Normalize text (replace underscores with spaces, uppercase severity) ──
  const normalizedText = typeof displayText === "string"
    ? displayText.replace(/_/g, " ").toUpperCase()
    : displayText;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        colorClasses,
        className
      )}
      {...props}
    >
      {/* Colored dot */}
      {withDot && !icon && (
        <span className={cn("h-1.5 w-1.5 rounded-full", dotClass)} />
      )}
      
      {/* Icon */}
      {icon && <span className="shrink-0">{icon}</span>}
      
      {/* Text */}
      {normalizedText}
    </span>
  );
}
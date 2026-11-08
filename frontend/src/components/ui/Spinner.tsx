/**
 * CyberGuard AI — Spinner Component
 * ============================================================================
 * 
 * A versatile loading indicator used throughout the app.
 * 
 * Modes:
 *   - **Inline (default)** — A simple spinning icon, sized for buttons 
 *     or small containers.
 *   - **Full-screen** — A fixed overlay with a semi-transparent backdrop, 
 *     used when blocking the whole UI during initial auth or data load.
 *   - **With label** — Adds text below the spinner (e.g., "Loading alerts...").
 * 
 * Accessibility:
 *   Uses `role="status"` and a screen-reader-only text label so assistive
 *   technologies announce "Loading..." when the spinner appears.
 */

import React from "react";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";


// ============================================================================
// TYPES
// ============================================================================

export interface SpinnerProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Size of the spinner icon */
  size?: "sm" | "md" | "lg" | "xl";
  
  /** Optional text to display below the spinner */
  label?: string;
  
  /** If true, renders a full-screen fixed overlay */
  fullScreen?: boolean;
  
  /** Overrides the default blue color */
  className?: string;
}


// ============================================================================
// SIZE MAP
// ============================================================================

const sizeClasses = {
  sm: "h-4 w-4",
  md: "h-6 w-6",
  lg: "h-8 w-8",
  xl: "h-12 w-12",
};


// ============================================================================
// COMPONENT
// ============================================================================

export function Spinner({
  size = "md",
  label,
  fullScreen = false,
  className,
  ...props
}: SpinnerProps) {
  
  // The core spinner (icon + optional label)
  const content = (
    <div
      role="status"
      aria-label={label || "Loading"}
      className={cn(
        "flex flex-col items-center justify-center gap-3",
        // If not fullScreen and no label, it's inline
        !fullScreen && !label && "inline-flex",
        className
      )}
      {...props}
    >
      <Loader2 
        className={cn(
          "animate-spin text-brand-600 dark:text-brand-500",
          sizeClasses[size]
        )} 
      />
      {label && (
        <p className="text-sm font-medium text-slate-500 dark:text-slate-400">
          {label}
        </p>
      )}
      
      {/* Screen reader only text */}
      <span className="sr-only">Loading...</span>
    </div>
  );

  // Wrap in a full-screen overlay if requested
  if (fullScreen) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-50/80 dark:bg-slate-950/80 backdrop-blur-sm">
        {content}
      </div>
    );
  }

  return content;
}
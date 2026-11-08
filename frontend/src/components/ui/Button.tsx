/**
 * CyberGuard AI — Button Component
 * ============================================================================
 * 
 * The foundational interactive element for the entire UI.
 * 
 * Features:
 *   - 5 visual variants (primary, secondary, danger, outline, ghost)
 *   - 3 sizes (sm, md, lg)
 *   - Built-in loading state (spinner + disabled)
 *   - Optional left/right icons
 *   - Full dark mode support
 *   - Accessible focus rings (keyboard navigation only)
 * 
 * Note: We use `forwardRef` so this component can be used with Radix UI 
 * primitives (like Dialog.Toggle or Dropdown.Trigger) later.
 */

import React, { forwardRef } from "react";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";


// ============================================================================
// TYPES
// ============================================================================

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "outline" | "ghost";
  size?: "sm" | "md" | "lg";
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}


// ============================================================================
// STYLES
// ============================================================================

const baseStyles = 
  "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors cursor-pointer " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 " +
  "dark:focus-visible:ring-offset-slate-950 disabled:pointer-events-none disabled:opacity-50 disabled:cursor-not-allowed";

const variants = {
  primary: 
    "bg-brand-600 text-white shadow-sm hover:bg-brand-700 active:bg-brand-800",
  secondary: 
    "bg-slate-100 text-slate-900 hover:bg-slate-200 active:bg-slate-300 " +
    "dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 dark:active:bg-slate-600",
  danger: 
    "bg-red-600 text-white shadow-sm hover:bg-red-700 active:bg-red-800",
  outline: 
    "border border-slate-300 bg-transparent text-slate-700 hover:bg-slate-100 " +
    "dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800",
  ghost: 
    "bg-transparent text-slate-700 hover:bg-slate-100 active:bg-slate-200 " +
    "dark:text-slate-300 dark:hover:bg-slate-800 dark:active:bg-slate-700",
};

const sizes = {
  sm: "h-8 px-3 text-xs [&>svg]:h-3.5 [&>svg]:w-3.5",
  md: "h-10 px-4 text-sm [&>svg]:h-4 [&>svg]:w-4",
  lg: "h-12 px-6 text-base [&>svg]:h-5 [&>svg]:w-5",
};


// ============================================================================
// COMPONENT
// ============================================================================

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = "primary",
      size = "md",
      isLoading = false,
      leftIcon,
      rightIcon,
      children,
      disabled,
      ...props
    },
    ref
  ) => {
    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(
          baseStyles,
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      >
        {/* If loading, show spinner in place of the left icon to prevent layout shift */}
        {isLoading && <Loader2 className="animate-spin" />}
        
        {/* Only show leftIcon if not loading */}
        {!isLoading && leftIcon && <span className="shrink-0">{leftIcon}</span>}
        
        {children}
        
        {/* Right icon is hidden during loading */}
        {!isLoading && rightIcon && <span className="shrink-0">{rightIcon}</span>}
      </button>
    );
  }
);

Button.displayName = "Button";
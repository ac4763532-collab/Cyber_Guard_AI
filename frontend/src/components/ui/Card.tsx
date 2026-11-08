/**
 * CyberGuard AI — Card Component
 * ============================================================================
 * 
 * The primary layout container for dashboard widgets, stats, and lists.
 * 
 * Built as a compound component pattern (Card.Header, Card.Title, etc.)
 * to keep the JSX clean and semantic.
 * 
 * Features:
 *   - Standardized borders, shadows, and border-radius
 *   - Full dark mode support
 *   - Optional interactive hover states (for clickable cards)
 *   - `forwardRef` on all subcomponents for Radix UI compatibility
 */

import React, { forwardRef } from "react";
import { cn } from "@/lib/utils";


// ============================================================================
// CARD CONTAINER
// ============================================================================

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Adds hover/active styles when the whole card is clickable */
  interactive?: boolean;
}

export const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ className, interactive, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "rounded-xl border border-slate-200 bg-white text-slate-900 shadow-sm overflow-hidden",
        "dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100",
        interactive && "cursor-pointer transition-all hover:border-brand-300 hover:shadow-md dark:hover:border-brand-700",
        className
      )}
      {...props}
    />
  )
);
Card.displayName = "Card";


// ============================================================================
// CARD HEADER
// ============================================================================

export type CardHeaderProps = React.HTMLAttributes<HTMLDivElement>;

export const CardHeader = forwardRef<HTMLDivElement, CardHeaderProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "flex flex-col gap-1.5 p-5 border-b border-slate-100 dark:border-slate-800",
        className
      )}
      {...props}
    />
  )
);
CardHeader.displayName = "CardHeader";


// ============================================================================
// CARD TITLE
// ============================================================================

export type CardTitleProps = React.HTMLAttributes<HTMLHeadingElement>;

export const CardTitle = forwardRef<HTMLHeadingElement, CardTitleProps>(
  ({ className, ...props }, ref) => (
    <h3
      ref={ref}
      className={cn(
        "text-lg font-semibold leading-none tracking-tight",
        className
      )}
      {...props}
    />
  )
);
CardTitle.displayName = "CardTitle";


// ============================================================================
// CARD DESCRIPTION
// ============================================================================

export type CardDescriptionProps = React.HTMLAttributes<HTMLParagraphElement>;

export const CardDescription = forwardRef<HTMLParagraphElement, CardDescriptionProps>(
  ({ className, ...props }, ref) => (
    <p
      ref={ref}
      className={cn(
        "text-sm text-slate-500 dark:text-slate-400",
        className
      )}
      {...props}
    />
  )
);
CardDescription.displayName = "CardDescription";


// ============================================================================
// CARD CONTENT
// ============================================================================

export type CardContentProps = React.HTMLAttributes<HTMLDivElement>;

export const CardContent = forwardRef<HTMLDivElement, CardContentProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("p-5", className)}
      {...props}
    />
  )
);
CardContent.displayName = "CardContent";


// ============================================================================
// CARD FOOTER
// ============================================================================

export type CardFooterProps = React.HTMLAttributes<HTMLDivElement>;

export const CardFooter = forwardRef<HTMLDivElement, CardFooterProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "flex items-center p-5 border-t border-slate-100 bg-slate-50/50 dark:border-slate-800 dark:bg-slate-900/50",
        className
      )}
      {...props}
    />
  )
);
CardFooter.displayName = "CardFooter";
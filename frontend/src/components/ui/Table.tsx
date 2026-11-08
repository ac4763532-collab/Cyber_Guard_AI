/**
 * CyberGuard AI — Table Components
 * ============================================================================
 * 
 * Semantic, accessible data table primitives.
 * 
 * SOC dashboards are fundamentally data tables. Rather than pulling in a
 * heavy headless library (like TanStack Table) right away, these primitives
 * provide 90% of the styling and accessibility we need out of the box.
 * 
 * Features:
 *   - Semantic HTML (`<table>`, `<thead>`, `<tbody>`, etc.)
 *   - Horizontal scroll wrapper for mobile/small screens
 *   - Sticky headers
 *   - Row hover states
 *   - Full dark mode support
 *   - `forwardRef` on all subcomponents
 */

import React, { forwardRef } from "react";
import { cn } from "@/lib/utils";


// ============================================================================
// TABLE WRAPPER (Handles overflow scroll)
// ============================================================================

export type TableWrapperProps = React.HTMLAttributes<HTMLDivElement>;

export const TableWrapper = forwardRef<HTMLDivElement, TableWrapperProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("w-full overflow-auto rounded-lg border border-slate-200 dark:border-slate-800", className)}
      {...props}
    />
  )
);
TableWrapper.displayName = "TableWrapper";


// ============================================================================
// MAIN TABLE
// ============================================================================

export type TableProps = React.TableHTMLAttributes<HTMLTableElement>;

export const Table = forwardRef<HTMLTableElement, TableProps>(
  ({ className, ...props }, ref) => (
    <table
      ref={ref}
      className={cn("w-full caption-bottom text-sm", className)}
      {...props}
    />
  )
);
Table.displayName = "Table";


// ============================================================================
// TABLE HEADER
// ============================================================================

export type TableHeaderProps = React.HTMLAttributes<HTMLTableSectionElement>;

export const TableHeader = forwardRef<HTMLTableSectionElement, TableHeaderProps>(
  ({ className, ...props }, ref) => (
    <thead
      ref={ref}
      className={cn(
        "bg-slate-50/80 sticky top-0 z-10 backdrop-blur-sm dark:bg-slate-900/80",
        className
      )}
      {...props}
    />
  )
);
TableHeader.displayName = "TableHeader";


// ============================================================================
// TABLE BODY
// ============================================================================

export type TableBodyProps = React.HTMLAttributes<HTMLTableSectionElement>;

export const TableBody = forwardRef<HTMLTableSectionElement, TableBodyProps>(
  ({ className, ...props }, ref) => (
    <tbody
      ref={ref}
      className={cn("[&_tr:last-child]:border-0", className)}
      {...props}
    />
  )
);
TableBody.displayName = "TableBody";


// ============================================================================
// TABLE ROW
// ============================================================================

export interface TableRowProps extends React.HTMLAttributes<HTMLTableRowElement> {
  /** Adds a clickable cursor and hover background */
  interactive?: boolean;
  /** Highlights the row (e.g., for a selected state) */
  selected?: boolean;
}

export const TableRow = forwardRef<HTMLTableRowElement, TableRowProps>(
  ({ className, interactive, selected, ...props }, ref) => (
    <tr
      ref={ref}
      className={cn(
        "border-b border-slate-200 transition-colors dark:border-slate-800",
        interactive && "cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50",
        selected && "bg-brand-50 dark:bg-brand-900/20 hover:bg-brand-100 dark:hover:bg-brand-900/30",
        className
      )}
      {...props}
    />
  )
);
TableRow.displayName = "TableRow";


// ============================================================================
// TABLE HEAD CELL (<th>)
// ============================================================================

export type TableHeadProps = React.ThHTMLAttributes<HTMLTableCellElement>;

export const TableHead = forwardRef<HTMLTableCellElement, TableHeadProps>(
  ({ className, ...props }, ref) => (
    <th
      ref={ref}
      className={cn(
        "h-10 px-4 text-left align-middle text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400",
        className
      )}
      {...props}
    />
  )
);
TableHead.displayName = "TableHead";


// ============================================================================
// TABLE DATA CELL (<td>)
// ============================================================================

export type TableCellProps = React.TdHTMLAttributes<HTMLTableCellElement>;

export const TableCell = forwardRef<HTMLTableCellElement, TableCellProps>(
  ({ className, ...props }, ref) => (
    <td
      ref={ref}
      className={cn("p-4 align-middle", className)}
      {...props}
    />
  )
);
TableCell.displayName = "TableCell";
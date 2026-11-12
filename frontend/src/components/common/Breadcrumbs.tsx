/**
 * CyberGuard AI — Breadcrumbs Component
 * ============================================================================
 * Minimalist, elegant breadcrumbs navigation with Microdata / Schema.org support.
 */

import React from "react";
import { Link, useLocation } from "react-router-dom";
import { ChevronRight, Home } from "lucide-react";
import { cn } from "@/lib/utils";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface BreadcrumbsProps {
  items?: BreadcrumbItem[];
  className?: string;
}

export function Breadcrumbs({ items, className }: BreadcrumbsProps) {
  const location = useLocation();

  // If items not provided, parse path segments
  const pathSegments = location.pathname.split("/").filter(Boolean);
  const breadcrumbList: BreadcrumbItem[] = items || pathSegments.map((segment, index) => {
    const href = "/" + pathSegments.slice(0, index + 1).join("/");
    // Format segment label cleanly (remove dashes, capitalize)
    const formatted = segment
      .replace(/-/g, " ")
      .replace(/\b\w/g, (char) => char.toUpperCase());
    return {
      label: formatted,
      href: index === pathSegments.length - 1 ? undefined : href,
    };
  });

  if (breadcrumbList.length === 0) return null;

  return (
    <nav
      aria-label="Breadcrumb"
      className={cn("flex items-center text-xs text-slate-500 dark:text-slate-400 font-medium py-1.5", className)}
    >
      <ol className="flex items-center space-x-1.5" itemScope itemType="https://schema.org/BreadcrumbList">
        <li className="flex items-center" itemProp="itemListElement" itemScope itemType="https://schema.org/ListItem">
          <Link
            to="/"
            className="flex items-center hover:text-slate-900 dark:hover:text-cyan-400 transition-colors"
            itemProp="item"
          >
            <Home className="h-3.5 w-3.5 mr-1" />
            <span itemProp="name" className="sr-only">Home</span>
          </Link>
          <meta itemProp="position" content="1" />
        </li>

        {breadcrumbList.map((item, index) => (
          <li
            key={index}
            className="flex items-center"
            itemProp="itemListElement"
            itemScope
            itemType="https://schema.org/ListItem"
          >
            <ChevronRight className="h-3 w-3 text-slate-400 mx-1 shrink-0" />
            {item.href ? (
              <Link
                to={item.href}
                className="hover:text-slate-900 dark:hover:text-cyan-400 transition-colors truncate max-w-[150px] sm:max-w-[200px]"
                itemProp="item"
              >
                <span itemProp="name">{item.label}</span>
              </Link>
            ) : (
              <span className="text-slate-900 dark:text-slate-200 font-semibold truncate max-w-[150px] sm:max-w-[200px]" itemProp="name">
                {item.label}
              </span>
            )}
            <meta itemProp="position" content={String(index + 2)} />
          </li>
        ))}
      </ol>
    </nav>
  );
}

export default Breadcrumbs;

/**
 * CyberGuard AI — Theme Toggle Switch Component
 * ============================================================================
 * Minimalist, animated button to switch between White (Light) and Dark mode.
 */

import React from "react";
import { Sun, Moon } from "lucide-react";
import { useTheme } from "@/theme/ThemeProvider";
import { cn } from "@/lib/utils";

interface ThemeToggleProps {
  className?: string;
  size?: "sm" | "md" | "lg";
}

export function ThemeToggle({ className, size = "md" }: ThemeToggleProps) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={isDark ? "Switch to white mode" : "Switch to dark mode"}
      title={isDark ? "Switch to white mode" : "Switch to dark mode"}
      className={cn(
        "relative inline-flex items-center justify-center rounded-xl transition-all duration-200",
        "bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200/80 shadow-sm",
        "dark:bg-slate-900/80 dark:hover:bg-slate-800 dark:text-slate-300 dark:hover:text-cyan-400 dark:border-slate-800",
        size === "sm" ? "h-8 w-8" : size === "lg" ? "h-10 w-10" : "h-9 w-9",
        className
      )}
    >
      <span className="sr-only">Toggle theme</span>
      {isDark ? (
        <Sun className="h-4 w-4 text-amber-400 transition-transform duration-300 rotate-0 hover:rotate-45" />
      ) : (
        <Moon className="h-4 w-4 text-slate-700 transition-transform duration-300 -rotate-12 hover:rotate-0" />
      )}
    </button>
  );
}

export default ThemeToggle;

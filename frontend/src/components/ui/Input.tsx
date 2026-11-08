/**
 * CyberGuard AI — Input Component
 * ============================================================================
 * 
 * A flexible, accessible text input used across all forms.
 * 
 * Features:
 *   - Optional label with required indicator
 *   - Error state styling (red border + text)
 *   - Helper text for instructions
 *   - Optional left/right icons
 *   - Password visibility toggle (eye icon)
 *   - Full dark mode support
 *   - `forwardRef` for integration with React Hook Form
 *   - Automatic unique ID generation for accessibility
 */

import React, { forwardRef, useId, useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import { cn } from "@/lib/utils";


// ============================================================================
// TYPES
// ============================================================================

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  containerClassName?: string;
}


// ============================================================================
// COMPONENT
// ============================================================================

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      className,
      containerClassName,
      type = "text",
      label,
      error,
      helperText,
      leftIcon,
      rightIcon,
      id,
      disabled,
      ...props
    },
    ref
  ) => {
    // Generate a unique ID if one isn't provided (for label-input linking)
    const generatedId = useId();
    const inputId = id || generatedId;
    
    // Password toggle state
    const [showPassword, setShowPassword] = useState(false);
    const isPasswordType = type === "password";
    const actualType = isPasswordType && showPassword ? "text" : type;

    return (
      <div className={cn("w-full flex flex-col gap-1.5", containerClassName)}>
        
        {/* ── Label ─────────────────────────────────────────────────── */}
        {label && (
          <label
            htmlFor={inputId}
            className="text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            {label}
            {props.required && <span className="ml-1 text-red-500">*</span>}
          </label>
        )}

        {/* ── Input Wrapper ───────────────────────────────────────────── */}
        <div className="relative flex items-center">
          
          {/* Left Icon */}
          {leftIcon && (
            <div className="absolute left-3 flex items-center justify-center text-slate-400 dark:text-slate-500">
              {leftIcon}
            </div>
          )}

          {/* The Input Element */}
          <input
            id={inputId}
            ref={ref}
            type={actualType}
            disabled={disabled}
            className={cn(
              "w-full rounded-lg border bg-white px-3 py-2 text-sm text-slate-900 shadow-sm transition-colors",
              "placeholder:text-slate-400 dark:placeholder:text-slate-500",
              "focus:outline-none focus:ring-2 focus:ring-brand-500",
              "disabled:cursor-not-allowed disabled:opacity-50",
              "dark:bg-slate-900 dark:text-slate-100",
              
              // Padding adjustments for icons
              leftIcon ? "pl-10" : "",
              (rightIcon || isPasswordType) ? "pr-10" : "",
              
              // Error vs Normal border
              error
                ? "border-red-300 focus:border-red-500 focus:ring-red-500 dark:border-red-800 dark:focus:ring-red-500"
                : "border-slate-300 focus:border-brand-500 dark:border-slate-700 dark:focus:border-brand-500",
              
              className
            )}
            aria-invalid={!!error}
            aria-describedby={
              error ? `${inputId}-error` : helperText ? `${inputId}-helper` : undefined
            }
            {...props}
          />

          {/* Right Icon OR Password Toggle */}
          <div className="absolute right-3 flex items-center justify-center">
            {isPasswordType ? (
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-slate-400 hover:text-slate-600 focus:outline-none dark:text-slate-500 dark:hover:text-slate-300"
                tabIndex={-1} // Don't interrupt tab flow from password to submit button
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            ) : (
              rightIcon && <div className="text-slate-400 dark:text-slate-500">{rightIcon}</div>
            )}
          </div>
        </div>

        {/* ── Error / Helper Text ────────────────────────────────────── */}
        {error ? (
          <p
            id={`${inputId}-error`}
            className="text-xs font-medium text-red-600 dark:text-red-400"
          >
            {error}
          </p>
        ) : helperText ? (
          <p
            id={`${inputId}-helper`}
            className="text-xs text-slate-500 dark:text-slate-400"
          >
            {helperText}
          </p>
        ) : null}
      </div>
    );
  }
);

Input.displayName = "Input";
/**
 * CyberGuard AI — Authentication Context
 * ============================================================================
 * 
 * Provides the global authentication state to the entire React tree.
 * 
 * Responsibilities:
 *   1. **Boot check** — On app load, checks for an existing token in
 *      localStorage. If found, validates it by calling `GET /auth/me`.
 *   2. **Auth actions** — Exposes `login()`, `register()`, and `logout()`.
 *   3. **Global 401 Handling** — Registers the `setUnauthorizedCallback`
 *      from `api.ts` so that if a token expires mid-session, the user
 *      is automatically logged out and redirected to /login.
 *   4. **Cache clearing** — On logout, wipes the React Query cache so
 *      one user never sees another user's data.
 */

import React, { createContext, useContext, useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, tokenStore, setUnauthorizedCallback } from "@/lib/api";
import type { User, TokenResponse } from "@/types";


// ============================================================================
// CONTEXT DEFINITION
// ============================================================================

export interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<User>;
  register: (email: string, password: string, fullName?: string, role?: string) => Promise<User>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);


// ============================================================================
// PROVIDER COMPONENT
// ============================================================================

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  
  const queryClient = useQueryClient();

  // ── Logout function (clears tokens, user state, and cache) ────────────
  const logout = () => {
    tokenStore.clear();
    setUser(null);
    queryClient.clear(); // Wipe all cached API data
    
    // Only redirect if we're not already on the login page
    if (window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
  };

  // ── Boot sequence (runs once on mount) ────────────────────────────────
  useEffect(() => {
    // 1. Register the global 401 callback (from api.ts)
    setUnauthorizedCallback(logout);

    // 2. Check for existing token
    const token = tokenStore.getAccess();
    if (!token) {
      setIsLoading(false);
      return;
    }

    // 3. Validate the token by fetching the user profile
    const fetchMe = async () => {
      try {
        const { data } = await api.get<User>("/auth/me");
        setUser(data);
      } catch (error) {
        // The `api` interceptor will try to refresh. If it fails, it 
        // calls `logout()` automatically. We just catch to prevent
        // an unhandled rejection warning.
        console.debug("Initial auth check failed:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchMe();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Login action ──────────────────────────────────────────────────────
  const login = async (email: string, password: string) => {
    // 1. Get tokens
    const { data: tokens } = await api.post<TokenResponse>("/auth/login", {
      email,
      password,
    });

    // 2. Persist tokens to localStorage
    tokenStore.set(tokens.access_token, tokens.refresh_token);

    // 3. Fetch the full user profile
    const { data: userProfile } = await api.get<User>("/auth/me");
    setUser(userProfile);
    return userProfile;
  };

  // ── Register action ───────────────────────────────────────────────────
  const register = async (email: string, password: string, fullName?: string, role?: string) => {
    // 1. Create account + get tokens
    const { data: tokens } = await api.post<TokenResponse>("/auth/register", {
      email,
      password,
      full_name: fullName,
      role: role || "individual",
    });

    // 2. Persist tokens
    tokenStore.set(tokens.access_token, tokens.refresh_token);

    // 3. Fetch profile
    // Note: The backend creates the user in PENDING_VERIFICATION status.
    // They are technically "logged in" but most actions will be blocked
    // until they verify their email.
    const { data: userProfile } = await api.get<User>("/auth/me");
    setUser(userProfile);
    return userProfile;
  };


  // ============================================================================
  // RENDER
  // ============================================================================

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}


// ============================================================================
// HOOK
// ============================================================================

/**
 * Access the current auth state. Throws if used outside `<AuthProvider>`.
 * 
 * Usage:
 *   const { user, logout, isAuthenticated } = useAuth();
 */
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
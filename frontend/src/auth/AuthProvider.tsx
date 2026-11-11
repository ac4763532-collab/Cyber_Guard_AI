/**
 * CyberGuard AI — Auth Provider & Session Manager
 * ============================================================================
 * 
 * Strict Enterprise Authentication Lifecycle:
 *   1. **Boot check** - On app load, checks for an existing token in
 *      localStorage. If found, validates it by calling `GET /auth/me`.
 *   2. **Auth actions** - Exposes `login()`, `register()`, `switchRole()`, and `logout()`.
 *   3. **Global 401 Handling** - Registers the `setUnauthorizedCallback`
 *      from `api.ts` so that if a token expires mid-session, the user
 *      is automatically logged out and redirected to /login.
 *   4. **Cache clearing** - On logout, wipes the React Query cache so
 *      one user never sees another user's data.
 */

import React, { createContext, useContext, useEffect, useState } from "react";
import { queryClient } from "@/lib/queryClient";
import { api, tokenStore, setUnauthorizedCallback } from "@/lib/api";
import type { User, TokenResponse } from "@/types";


// ============================================================================
// CONTEXT DEFINITION
// ============================================================================

export interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, targetRole?: string) => Promise<User>;
  register: (email: string, password: string, fullName?: string, role?: string) => Promise<User>;
  switchRole: (newRole: string) => Promise<User>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);


// ============================================================================
// PROVIDER COMPONENT
// ============================================================================

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // ── Logout action ──────────────────────────────────────────────────────
  const logout = () => {
    tokenStore.clear();  // Clear access & refresh tokens
    setUser(null);
    queryClient.clear(); // Wipe all cached API data
    
    // Only redirect if we're not already on the login page
    if (window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
  };

  // ── Boot sequence (runs once on mount) ─────────────────────────────────
  useEffect(() => {
    // 1. Wire the 401 handler so expired tokens trigger a clean logout
    setUnauthorizedCallback(() => {
      logout();
    });

    // 2. Validate any token left over from a previous session
    const initializeAuth = async () => {
      const token = tokenStore.getAccess();
      if (!token) {
        setIsLoading(false);
        return;
      }

      try {
        // Validate with the backend
        const { data: userProfile } = await api.get<User>("/auth/me");
        setUser(userProfile);
      } catch (error) {
        // Token is invalid, expired, or user suspended
        tokenStore.clear();
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Login action ──────────────────────────────────────────────────────
  const login = async (email: string, password: string, targetRole?: string) => {
    // 1. Get tokens (passing target_role if specified)
    const { data: tokens } = await api.post<TokenResponse>("/auth/login", {
      email,
      password,
      ...(targetRole ? { target_role: targetRole } : {}),
    });

    // 2. Persist tokens to localStorage
    tokenStore.set(tokens.access_token, tokens.refresh_token);

    // 3. Fetch the full user profile
    const { data: userProfile } = await api.get<User>("/auth/me");
    setUser(userProfile);
    return userProfile;
  };

  // ── Switch Workspace Role action ──────────────────────────────────────
  const switchRole = async (newRole: string) => {
    const { data: tokens } = await api.post<TokenResponse>("/auth/switch-role", {
      role: newRole,
    });

    tokenStore.set(tokens.access_token, tokens.refresh_token);
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
        switchRole,
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

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

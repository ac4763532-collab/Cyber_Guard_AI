/**
 * CyberGuard AI — API Client
 * ============================================================================
 * 
 * The Axios instance used by the entire frontend to talk to the backend.
 * 
 * Features:
 *   1. **Vite Proxy Base URL** — `/api/v1`. The Vite dev server forwards
 *      this to `localhost:8000`. In production, nginx does the forwarding.
 * 
 *   2. **Automatic Auth Headers** — The request interceptor reads the
 *      JWT from localStorage and attaches `Authorization: Bearer <token>`.
 * 
 *   3. **Silent Token Refresh** — The response interceptor catches 401s.
 *      If the access token is expired, it uses the refresh token to get
 *      a new pair. It queues concurrent requests during the refresh
 *      so the backend isn't spammed with 10 refresh calls.
 * 
 *   4. **Error Normalization** — Converts the backend's JSON error
 *      envelope (`{"error": {"code": "...", "message": "..."}}`) into
 *      a standard JS `Error` object. Components can then just render
 *      `error.message` in a toast.
 */

import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";


// ============================================================================
// TOKEN STORAGE
// ============================================================================
// For an MVP, we store tokens in localStorage. (In a highly secure
// enterprise app, we'd use HttpOnly cookies, but that requires backend
// changes to support cookie-based auth and CSRF tokens). 

const ACCESS_TOKEN_KEY = "cg_access_token";
const REFRESH_TOKEN_KEY = "cg_refresh_token";

export const tokenStore = {
  getAccess: () => localStorage.getItem(ACCESS_TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_TOKEN_KEY),
  
  set: (access: string, refresh: string) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, access);
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  },
  
  clear: () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  },
};


// ============================================================================
// UNAUTHORIZED CALLBACK
// ============================================================================
// Because this file exists outside the React component tree, it cannot
// use React Router's `useNavigate` hook. Instead, the AuthProvider
// registers a callback here. When a refresh fails completely, we call
// this to redirect the user to /login.

let unauthorizedCallback: (() => void) | null = null;

export function setUnauthorizedCallback(fn: () => void) {
  unauthorizedCallback = fn;
}


// ============================================================================
// AXIOS INSTANCE
// ============================================================================

export const api = axios.create({
  baseURL: "/api/v1",
  headers: { "Content-Type": "application/json" },
  timeout: 30_000, // 30 seconds (matches backend http_timeout_seconds)
});


// ============================================================================
// REQUEST INTERCEPTOR
// ============================================================================

api.interceptors.request.use((config) => {
  const token = tokenStore.getAccess();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});


// ============================================================================
// RESPONSE INTERCEPTOR (Refresh Queue)
// ============================================================================

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: any) => void;
}> = [];

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else if (token) {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
    
    // If it's not a 401, or it's a login/refresh request, fail immediately
    if (
      error.response?.status !== 401 || 
      originalRequest.url?.includes("/auth/login") || 
      originalRequest.url?.includes("/auth/refresh")
    ) {
      return Promise.reject(normalizeError(error));
    }

    // If we've already retried this exact request, give up
    if (originalRequest._retry) {
      tokenStore.clear();
      if (unauthorizedCallback) unauthorizedCallback();
      return Promise.reject(normalizeError(error));
    }

    // If a refresh is already in progress, queue this request
    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject });
      })
        .then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        })
        .catch((err) => {
          return Promise.reject(err);
        });
    }

    // Start the refresh process
    originalRequest._retry = true;
    isRefreshing = true;

    const refreshToken = tokenStore.getRefresh();
    if (!refreshToken) {
      tokenStore.clear();
      isRefreshing = false;
      if (unauthorizedCallback) unauthorizedCallback();
      return Promise.reject(normalizeError(error));
    }

    try {
      // Use a fresh Axios call to avoid circular interceptor loops
      const { data } = await axios.post("/api/v1/auth/refresh", {
        refresh_token: refreshToken,
      });

      tokenStore.set(data.access_token, data.refresh_token);
      
      // Update the default header for future requests
      api.defaults.headers.common.Authorization = `Bearer ${data.access_token}`;
      
      processQueue(null, data.access_token);
      originalRequest.headers.Authorization = `Bearer ${data.access_token}`;
      
      return api(originalRequest);
    } catch (refreshError) {
      processQueue(normalizeError(refreshError as AxiosError), null);
      tokenStore.clear();
      if (unauthorizedCallback) unauthorizedCallback();
      return Promise.reject(normalizeError(refreshError as AxiosError));
    } finally {
      isRefreshing = false;
    }
  }
);


// ============================================================================
// ERROR NORMALIZATION
// ============================================================================

/**
 * Converts an Axios error into a clean Error object that React Query
 * and our toast notifications can consume easily.
 */
function normalizeError(error: AxiosError): Error {
  if (error.response?.data) {
    const data = error.response.data as any;
    
    // 1. Standard CyberGuard Error Envelope
    if (data.error && data.error.message) {
      const err = new Error(data.error.message);
      (err as any).code = data.error.code;
      (err as any).status = error.response.status;
      (err as any).details = data.error.details;
      return err;
    }
    
    // 2. FastAPI/Pydantic Validation Errors (422)
    if (data.detail && Array.isArray(data.detail)) {
      const msg = data.detail
        .map((d: any) => `${d.loc[d.loc.length - 1]}: ${d.msg}`)
        .join(", ");
      return new Error(msg || "Validation error");
    }
    
    // 3. Generic fallback
    if (typeof data.detail === "string") {
      return new Error(data.detail);
    }
  }

  // Network errors, timeouts, etc.
  return new Error(error.message || "An unexpected error occurred");
}
/**
 * CyberGuard AI — React Query Client
 * ============================================================================
 * 
 * Configures the global state manager for server data (React Query).
 * 
 * Why React Query?
 * ----------------
 * The dashboard is a highly dynamic SOC (Security Operations Center) view.
 * We need to poll for new alerts, cache user profiles, and handle
 * loading/error states seamlessly. React Query eliminates the need for
 * hundreds of lines of `useEffect` + `useState` boilerplate.
 * 
 * Defaults chosen for CyberGuard:
 * 1. **staleTime: 60s** — Data is considered "fresh" for 1 minute. We 
 *    don't want to hammer the backend on every tab switch, but we also
 *    want reasonably up-to-date alerts.
 * 2. **refetchOnWindowFocus: false** — In a SOC, users often alt-tab 
 *    between tools. Refetching all queries every time the window focuses
 *    causes unnecessary network spikes. (We will use WebSockets or 
 *    explicit polling for real-time features later).
 * 3. **retry logic** — Do NOT retry 401/403 (auth) or 404 (not found) 
 *    errors. Retrying an expired token just wastes time. Do retry 
 *    network errors or 500s (transient backend issues).
 */

import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Wait 1 minute before considering data "stale"
      staleTime: 60 * 1000,
      
      // Keep unused data in memory for 5 minutes (e.g. if you navigate away and come back)
      gcTime: 5 * 60 * 1000,
      
      // Don't refetch just because the user clicked back into the browser window
      refetchOnWindowFocus: false,
      
      // Retry network/500 errors up to 2 times, but fail immediately on 4xx
      retry: (failureCount, error: any) => {
        // If it's a 4xx error (except 429 Too Many Requests), don't retry
        const status = error?.status;
        if (status >= 400 && status < 500 && status !== 429) {
          return false;
        }
        // For 500s or network errors, retry up to 2 times
        return failureCount < 2;
      },
      
      // Exponential backoff for retries: 1s, 2s, 4s, etc.
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
    },
    mutations: {
      // Mutations (POST/PATCH/DELETE) should generally not be automatically retried
      // to avoid duplicate actions (like creating two incidents).
      retry: false,
    },
  },
});
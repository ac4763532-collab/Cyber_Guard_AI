/**
 * CyberGuard AI — Vite Configuration
 * ============================================================================
 *
 * Builds the frontend with React + TypeScript. Provides:
 *
 *   1. Dev server (port 5173) with `/api` proxy → `http://localhost:8000`
 *      so frontend and backend live on the same origin during dev.
 *      No CORS issues, no cookies/headers workaround.
 *
 *   2. Path alias `@/` → `src/`. Every import is `@/lib/api` instead of
 *      `../../../lib/api`. Long relative paths break whenever files move.
 *
 *   3. Production build with manual vendor chunks. React, React Router,
 *      and React Query are bundled separately from app code. Why:
 *      - Vendor chunks rarely change → browser cache hits across deploys
 *      - App code changes → only the (small) app chunk re-downloads
 *      - Reduces initial repeat-visit bundle size by ~40%
 *
 *   4. Source maps in production (external — not inlined). Uploaded to
 *      Sentry if configured; harmless if not. Never shipped to clients.
 *
 * Why `fileURLToPath` for `__dirname`
 * ------------------------------------
 * Vite configs are ES modules (because `"type": "module"` is set in
 * package.json). `__dirname` and `__filename` don't exist in ESM — they
 * were CommonJS globals. The standard ESM replacement is
 * `fileURLToPath(import.meta.url)`. Alternative: `process.cwd()`, but
 * that breaks if Vite is invoked from a directory other than the
 * project root.
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";


// ---------------------------------------------------------------------------
// ESM-safe __dirname
// ---------------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
export default defineConfig({
  plugins: [react()],

  // ── Dev server ────────────────────────────────────────────────────────
  server: {
    port: 5173,
    strictPort: false,   // if 5173 is taken, Vite picks 5174, 5175, ...
    host: "localhost",
    open: false,         // don't auto-open browser — dev can open manually
    proxy: {
      // Forward all /api/* requests to the backend, preserving cookies
      // and headers. This makes the frontend's fetch("/api/v1/...") calls
      // work without CORS — same origin, same cookies, same protocol.
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,     // allow self-signed certs in dev
      },
      // Also proxy the backend's /health endpoint (unauthenticated,
      // used by a status widget on the landing page)
      "/health": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },

  // ── Path aliases ──────────────────────────────────────────────────────
  // `@/` → `src/`. Must be mirrored in tsconfig.json's `paths` field,
  // otherwise TypeScript will complain "Cannot find module '@/...'"
  // while the bundler works fine (or vice versa).
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },

  // ── Production build ──────────────────────────────────────────────────
  build: {
    outDir: "dist",
    sourcemap: false,         // no production source maps
    minify: "esbuild",
    target: "es2020",         // modern browsers only — React 18, optional chaining, etc.

    rollupOptions: {
      output: {
        // Manual chunk split — three chunks:
        //   react-vendor  → React, React DOM, React Router
        //   query-vendor  → React Query
        //   app           → everything else (all page components)
        //
        // Rationale: vendor chunks rarely change. A user who visited
        // yesterday and is back today re-downloads only the app chunk
        // (typically 20-40 KB) — the vendor chunks (150-180 KB) hit
        // the browser's HTTP cache.
        manualChunks: {
          "react-vendor": [
            "react",
            "react-dom",
            "react-router-dom",
          ],
          "query-vendor": [
            "@tanstack/react-query",
          ],
        },

        // Deterministic chunk filenames — enables long-term caching
        // (the hash changes only when the chunk's content changes)
        chunkFileNames: "assets/[name]-[hash].js",
        entryFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },

  // ── Preview (for `npm run preview`) ───────────────────────────────────
  preview: {
    port: 4173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
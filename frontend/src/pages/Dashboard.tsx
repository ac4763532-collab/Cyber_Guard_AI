/**
 * CyberGuard AI — Dashboard Page
 * ============================================================================
 * 
 * The primary landing page for authenticated users.
 * 
 * Data Fetching:
 *   - Uses React Query (`useQuery`) to fetch 4 independent datasets in parallel.
 *   - Handles loading state with skeletons/spinners.
 *   - Handles error state (e.g., if the backend is unreachable).
 *   - Handles empty state (e.g., "No alerts yet").
 * 
 * Layout:
 *   - Row 1: Key Metrics (Alerts, Incidents, Cases) as clickable cards.
 *   - Row 2: Device Health (list of connected sources).
 *   - Row 3: Recent Alerts Table.
 */

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Bell, Shield, FolderOpen, Server, ArrowRight, CheckCircle2, XCircle } from "lucide-react";

import { api } from "@/lib/api";
import type {
  PaginatedResponse,
  SecurityAlert,
  SecurityIncident,
  SecurityCase,
} from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { Button } from "@/components/ui/Button";
import { formatRelativeTime } from "@/lib/utils";


// ============================================================================
// DATA FETCHING HOOKS
// ============================================================================

// Fetch recent alerts (limit 5)
function useRecentAlerts() {
  return useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<SecurityAlert>>("/alerts", {
        params: { page: 1, page_size: 5 },
      });
      return data;
    },
  });
}

// Fetch open incidents count
function useOpenIncidents() {
  return useQuery({
    queryKey: ["incidents", "open"],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<SecurityIncident>>("/incidents", {
        params: { page: 1, page_size: 1, status: "open" },
      });
      return data;
    },
  });
}

// Fetch active cases count
function useActiveCases() {
  return useQuery({
    queryKey: ["cases", "active"],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<SecurityCase>>("/cases", {
        params: { page: 1, page_size: 1, status: "investigating" },
      });
      return data;
    },
  });
}

// Fetch device health (sources)
function useSources() {
  return useQuery({
    queryKey: ["sources", "dashboard"],
    queryFn: async () => {
      // Using a generic record here as the source schema might have fields
      // we didn't map in types/index.ts yet. We just need name + status.
      const { data } = await api.get<PaginatedResponse<any>>("/sources", {
        params: { page: 1, page_size: 10 },
      });
      return data;
    },
  });
}


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Dashboard() {
  const alertsQuery = useRecentAlerts();
  const incidentsQuery = useOpenIncidents();
  const casesQuery = useActiveCases();
  const sourcesQuery = useSources();

  // Helper to safely extract total counts
  const alertCount = alertsQuery.data?.meta.total ?? 0;
  const incidentCount = incidentsQuery.data?.meta.total ?? 0;
  const caseCount = casesQuery.data?.meta.total ?? 0;

  return (
    <div className="space-y-6">
      
      {/* ── Page Header ────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Security Overview
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Here's what's happening across your workspaces today.
        </p>
      </div>

      {/* ── Metrics Row ────────────────────────────────────────────────── */}
      <div className="grid gap-4 md:grid-cols-3">
        {/* Alerts Card */}
        <Link to="/alerts">
          <Card interactive className="h-full">
            <CardContent className="flex items-center gap-4 p-6">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400">
                <Bell size={24} />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">
                  Open Alerts
                </p>
                <div className="flex items-baseline gap-2">
                  <h2 className="text-3xl font-bold text-slate-900 dark:text-slate-100">
                    {alertsQuery.isLoading ? "..." : alertCount}
                  </h2>
                </div>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Incidents Card */}
        <Link to="/incidents">
          <Card interactive className="h-full">
            <CardContent className="flex items-center gap-4 p-6">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400">
                <Shield size={24} />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">
                  Open Incidents
                </p>
                <div className="flex items-baseline gap-2">
                  <h2 className="text-3xl font-bold text-slate-900 dark:text-slate-100">
                    {incidentsQuery.isLoading ? "..." : incidentCount}
                  </h2>
                </div>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Cases Card */}
        <Link to="/cases">
          <Card interactive className="h-full">
            <CardContent className="flex items-center gap-4 p-6">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
                <FolderOpen size={24} />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">
                  Active Cases
                </p>
                <div className="flex items-baseline gap-2">
                  <h2 className="text-3xl font-bold text-slate-900 dark:text-slate-100">
                    {casesQuery.isLoading ? "..." : caseCount}
                  </h2>
                </div>
              </div>
            </CardContent>
          </Card>
        </Link>
      </div>

      {/* ── Bottom Row (Alerts Table + Device Health) ──────────────────── */}
      <div className="grid gap-6 lg:grid-cols-3">
        
        {/* Recent Alerts Table (Takes 2/3 width) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              Recent Alerts
            </h2>
            <Link to="/alerts">
              <Button variant="ghost" size="sm" rightIcon={<ArrowRight size={16} />}>
                View All
              </Button>
            </Link>
          </div>

          <Card>
            {alertsQuery.isLoading ? (
              <div className="p-8">
                <Spinner label="Loading alerts..." />
              </div>
            ) : alertsQuery.isError ? (
              <div className="p-8 text-center text-sm text-red-500">
                Failed to load alerts. Is the backend running?
              </div>
            ) : alertsQuery.data?.items.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-500">
                No alerts found. Your environment looks quiet!
              </div>
            ) : (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {alertsQuery.data?.items.map((alert) => (
                  <Link 
                    key={alert.id} 
                    to={`/alerts/${alert.id}`}
                    className="flex items-center justify-between p-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2">
                        <Badge severity={alert.severity} />
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {alert.title}
                        </span>
                      </div>
                      <span className="text-xs text-slate-500">
                        {formatRelativeTime(alert.first_seen_at)}
                      </span>
                    </div>
                    <Badge status={alert.status} withDot />
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Device Health (Takes 1/3 width) */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              Device Health
            </h2>
            <Link to="/devices">
              <Button variant="ghost" size="sm" rightIcon={<ArrowRight size={16} />}>
                Manage
              </Button>
            </Link>
          </div>
          
          <Card>
            <CardContent className="p-0">
              {sourcesQuery.isLoading ? (
                <div className="p-8">
                  <Spinner label="Checking devices..." />
                </div>
              ) : sourcesQuery.isError ? (
                <div className="p-8 text-center text-sm text-red-500">
                  Failed to load devices.
                </div>
              ) : sourcesQuery.data?.items.length === 0 ? (
                <div className="p-8 text-center text-sm text-slate-500">
                  No devices connected yet.
                </div>
              ) : (
                <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                  {sourcesQuery.data?.items.map((source: any) => (
                    <li key={source.id} className="flex items-center justify-between p-4">
                      <div className="flex items-center gap-3">
                        <Server size={18} className="text-slate-400" />
                        <div>
                          <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                            {source.name}
                          </p>
                          <p className="text-xs text-slate-500">
                            {source.hostname || source.source_type}
                          </p>
                        </div>
                      </div>
                      {source.collector_connected ? (
                        <div className="flex items-center gap-1 text-xs font-medium text-green-600 dark:text-green-400">
                          <CheckCircle2 size={14} />
                          Online
                        </div>
                      ) : (
                        <div className="flex items-center gap-1 text-xs font-medium text-slate-400">
                          <XCircle size={14} />
                          Offline
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

      </div>
    </div>
  );
}
/**
 * CyberGuard AI — Cases Page
 * ============================================================================
 * 
 * Manages the investigation cases.
 * 
 * This page is shared by both Clients (Normal Users) and Analysts:
 *   - **Clients** see the cases they created by hiring analysts via the
 *     Marketplace.
 *   - **Analysts** see the cases assigned to them.
 * 
 * Features:
 *   - Filter by Status and Priority.
 *   - Search by Case Number or Title.
 *   - Click a case to open the Case Detail (Conversation + Evidence).
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Search, ChevronLeft, ChevronRight, FolderOpen, Plus } from "lucide-react";

import { api } from "@/lib/api";
import type { PaginatedResponse, SecurityCase, CaseStatus, CasePriority } from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";
import { formatRelativeTime } from "@/lib/utils";


// ============================================================================
// TYPES & CONSTANTS
// ============================================================================

const STATUS_OPTIONS: CaseStatus[] = [
  "open", "assigned", "investigating", "pending_client", 
  "pending_info", "resolved", "closed", "cancelled"
];

const PRIORITY_OPTIONS: CasePriority[] = [
  "urgent", "high", "medium", "low"
];

// Maps CasePriority to our severity Badge colors
const priorityToSeverity = (priority: string) => {
  if (priority === "urgent") return "critical";
  if (priority === "high") return "high";
  if (priority === "medium") return "medium";
  return "low";
};


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Cases() {
  // ── State ─────────────────────────────────────────────────────────────
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<CaseStatus | "all">("all");
  const [priorityFilter, setPriorityFilter] = useState<CasePriority | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");

  // ── Data Fetching ─────────────────────────────────────────────────────
  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ["cases", page, statusFilter, priorityFilter, searchQuery],
    queryFn: async () => {
      const params: Record<string, any> = {
        page,
        page_size: 15,
      };
      if (statusFilter !== "all") params.status = statusFilter;
      if (priorityFilter !== "all") params.priority = priorityFilter;
      if (searchQuery) params.title_contains = searchQuery;

      const { data } = await api.get<PaginatedResponse<SecurityCase>>("/cases", { params });
      return data;
    },
  });

  // ============================================================================
  // RENDER
  // ============================================================================

  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Cases
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Track investigations, communicate with analysts, and review findings.
          </p>
        </div>
        
        {/* Note: In a fully production flow, cases are created automatically
            when you purchase an offering in the Marketplace. This button
            is here for Admins who want to manually create a case. */}
        <Button leftIcon={<Plus size={16} />}>
          Create Case
        </Button>
      </div>

      {/* ── Toolbar ────────────────────────────────────────────────────── */}
      <Card>
        <CardContent className="p-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          
          <div className="w-full sm:max-w-xs">
            <Input
              placeholder="Search cases..."
              leftIcon={<Search size={16} />}
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <div className="flex flex-wrap items-center gap-4">
            {/* Status Filter */}
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-500 dark:text-slate-400 hidden sm:inline">Status:</span>
              <select
                className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                value={statusFilter}
                onChange={(e) => { setStatusFilter(e.target.value as any); setPage(1); }}
              >
                <option value="all">All Statuses</option>
                {STATUS_OPTIONS.map((s) => (
                  <option key={s} value={s}>{s.replace("_", " ").toUpperCase()}</option>
                ))}
              </select>
            </div>

            {/* Priority Filter */}
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-500 dark:text-slate-400 hidden sm:inline">Priority:</span>
              <select
                className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                value={priorityFilter}
                onChange={(e) => { setPriorityFilter(e.target.value as any); setPage(1); }}
              >
                <option value="all">All Priorities</option>
                {PRIORITY_OPTIONS.map((p) => (
                  <option key={p} value={p}>{p.toUpperCase()}</option>
                ))}
              </select>
            </div>
          </div>

        </CardContent>
      </Card>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading cases..." /></CardContent></Card>
      ) : isError ? (
        <Card><CardContent className="p-12 text-center text-red-500">Failed to load cases.</CardContent></Card>
      ) : data?.items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center p-12 text-center">
            <FolderOpen size={48} className="text-slate-300 dark:text-slate-600 mb-4" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">No cases found</h3>
            <p className="mt-1 text-sm text-slate-500 max-w-sm">
              You don't have any active cases. If you need help investigating an alert, hire an analyst in the Marketplace.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Case #</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead className="hidden md:table-cell">Status</TableHead>
                  <TableHead className="hidden md:table-cell">Opened</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((c) => (
                  <TableRow key={c.id} interactive>
                    <TableCell className="font-mono text-xs text-slate-500">
                      {c.case_number}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {c.title}
                        </span>
                        {c.is_billable && (
                          <span className="text-xs font-medium text-brand-600 dark:text-brand-400">
                            Paid Engagement
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge severity={priorityToSeverity(c.priority)} label={c.priority} />
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <Badge status={c.status} withDot />
                    </TableCell>
                    <TableCell className="hidden md:table-cell text-sm text-slate-500">
                      {formatRelativeTime(c.opened_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Link to={`/cases/${c.id}`}>
                        <Button variant="ghost" size="sm">View</Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableWrapper>

          {/* Pagination */}
          <div className="flex items-center justify-between border-t border-slate-200 pt-4 dark:border-slate-800">
            <div className="text-sm text-slate-500 dark:text-slate-400">
              Showing <span className="font-medium">{(page - 1) * 15 + 1}</span> to{" "}
              <span className="font-medium">
                {Math.min(page * 15, data?.meta.total || 0)}
              </span>{" "}
              of <span className="font-medium">{data?.meta.total}</span> results
            </div>
            
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage(p => p - 1)} disabled={!data?.meta.has_prev || isFetching} leftIcon={<ChevronLeft size={16} />}>Previous</Button>
              <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={!data?.meta.has_next || isFetching} rightIcon={<ChevronRight size={16} />}>Next</Button>
            </div>
          </div>
        </>
      )}

    </div>
  );
}
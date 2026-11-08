/**
 * CyberGuard AI — Admin: Audit Logs Page
 * ============================================================================
 * 
 * The forensic record of everything that happens on the platform.
 * 
 * Features:
 *   - Immutable table of events (logins, approvals, case closures, etc.)
 *   - Bounding filters (required by the backend to prevent massive scans).
 *   - Detailed Modal showing the "Before" and "After" state of changes.
 *   - Correlation ID included for tracing backend logs.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Shield, Eye, Filter } from "lucide-react";

import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription } from "@/components/ui/Modal";
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";
import { formatDate } from "@/lib/utils";


// ============================================================================
// TYPES
// ============================================================================

interface AuditLog {
  id: string;
  timestamp: string;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  target_type: string;
  target_id: string | null;
  target_display: string | null;
  ip_address: string | null;
  user_agent: string | null;
  before_state: Record<string, any> | null;
  after_state: Record<string, any> | null;
  metadata: Record<string, any> | null;
  correlation_id: string | null;
}


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function AuditLogs() {
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  // ── Data Fetching ─────────────────────────────────────────────────────
  const { data, isLoading, isError } = useQuery({
    queryKey: ["audit-logs", page, searchQuery, actionFilter],
    queryFn: async () => {
      // Backend requires at least one bounding filter to prevent full-table scans.
      // We default to the last 7 days if no specific search is performed.
      const params: Record<string, any> = {
        page,
        page_size: 20,
        created_after: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      };

      if (searchQuery) params.actor_email = searchQuery;
      if (actionFilter !== "all") params.action = actionFilter;

      const { data } = await api.get<PaginatedResponse<AuditLog>>("/admin/audit", { params });
      return data;
    },
  });

  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 flex items-center gap-2">
          <Shield className="text-brand-600" /> Audit Logs
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Immutable record of system activities and user actions. Showing last 7 days by default.
        </p>
      </div>

      {/* ── Toolbar ────────────────────────────────────────────────────── */}
      <Card>
        <CardContent className="p-4 flex flex-col gap-4 sm:flex-row sm:items-center">
          <div className="w-full sm:max-w-xs">
            <Input
              placeholder="Filter by actor email..."
              leftIcon={<Search size={16} />}
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
            />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-500 dark:text-slate-400 flex items-center gap-1">
              <Filter size={14} /> Action:
            </span>
            <select
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
              value={actionFilter}
              onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
            >
              <option value="all">All Actions</option>
              <option value="auth.login">Login</option>
              <option value="user.self_updated">Profile Updated</option>
              <option value="incident.created">Incident Created</option>
              <option value="alert.resolved">Alert Resolved</option>
              <option value="analyst.verified">Analyst Approved</option>
            </select>
          </div>
        </CardContent>
      </Card>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading audit logs..." /></CardContent></Card>
      ) : isError ? (
        <Card><CardContent className="p-12 text-center text-red-500">Failed to load audit logs. You may lack permission.</CardContent></Card>
      ) : data?.items.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center text-slate-500">
            No audit logs found for the selected filters.
          </CardContent>
        </Card>
      ) : (
        <>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[160px]">Timestamp</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="hidden md:table-cell">Target</TableHead>
                  <TableHead className="text-right">Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell className="text-xs text-slate-500 font-mono">
                      {formatDate(log.timestamp)}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {log.actor_email || "System"}
                        </span>
                        <span className="text-xs text-slate-500">{log.ip_address || "Internal"}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" label={log.action} className="font-mono text-[10px]" />
                    </TableCell>
                    <TableCell className="hidden md:table-cell text-sm text-slate-500">
                      {log.target_display || log.target_type}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => setSelectedLog(log)} leftIcon={<Eye size={14} />}>
                        View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableWrapper>

          {/* Pagination */}
          <div className="flex items-center justify-between border-t border-slate-200 pt-4 dark:border-slate-800">
            <div className="text-sm text-slate-500">
              Showing <span className="font-medium">{(page - 1) * 20 + 1}</span> to{" "}
              <span className="font-medium">{Math.min(page * 20, data?.meta.total || 0)}</span> of{" "}
              <span className="font-medium">{data?.meta.total}</span> results
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage(p => p - 1)} disabled={!data?.meta.has_prev}>
                Previous
              </Button>
              <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={!data?.meta.has_next}>
                Next
              </Button>
            </div>
          </div>
        </>
      )}

      <AuditLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  );
}


// ============================================================================
// DETAIL MODAL
// ============================================================================

function AuditLogDetailModal({ log, onClose }: { log: AuditLog | null; onClose: () => void }) {
  if (!log) return null;

  return (
    <Modal open={!!log} onOpenChange={(open) => !open && onClose()}>
      <ModalContent className="max-w-3xl">
        <ModalHeader>
          <ModalTitle>Audit Event Details</ModalTitle>
          <ModalDescription>
            Recorded at {formatDate(log.timestamp)}
          </ModalDescription>
        </ModalHeader>

        <div className="py-4 space-y-6 max-h-[60vh] overflow-y-auto">
          
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-slate-500">Action</p>
              <p className="font-mono font-medium">{log.action}</p>
            </div>
            <div>
              <p className="text-slate-500">Target</p>
              <p className="font-medium">{log.target_type} ({log.target_id || "N/A"})</p>
            </div>
            <div>
              <p className="text-slate-500">Correlation ID</p>
              <p className="font-mono text-xs break-all">{log.correlation_id || "None"}</p>
            </div>
            <div>
              <p className="text-slate-500">User Agent</p>
              <p className="text-xs truncate" title={log.user_agent || ""}>{log.user_agent || "Unknown"}</p>
            </div>
          </div>

          {/* State Diff */}
          {(log.before_state || log.after_state) && (
            <div className="space-y-4">
              <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 border-b pb-2">State Changes</h4>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs font-medium text-red-500 mb-1">BEFORE</p>
                  <pre className="rounded-md bg-slate-100 p-3 text-xs overflow-x-auto dark:bg-slate-950 dark:text-slate-300">
                    {JSON.stringify(log.before_state || {}, null, 2)}
                  </pre>
                </div>
                <div>
                  <p className="text-xs font-medium text-green-500 mb-1">AFTER</p>
                  <pre className="rounded-md bg-slate-100 p-3 text-xs overflow-x-auto dark:bg-slate-950 dark:text-slate-300">
                    {JSON.stringify(log.after_state || {}, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* Additional Metadata */}
          {log.metadata && (
            <div>
              <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 border-b pb-2 mb-2">Metadata</h4>
              <pre className="rounded-md bg-slate-100 p-3 text-xs overflow-x-auto dark:bg-slate-950 dark:text-slate-300">
                {JSON.stringify(log.metadata, null, 2)}
              </pre>
            </div>
          )}

        </div>
      </ModalContent>
    </Modal>
  );
}
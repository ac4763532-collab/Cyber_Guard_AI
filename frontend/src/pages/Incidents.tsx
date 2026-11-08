/**
 * CyberGuard AI — Incidents Page
 * ============================================================================
 * 
 * Manages the full NIST SP 800-61 incident lifecycle.
 * 
 * Features:
 *   - Table with NIST status filtering (open, investigating, containment, etc.)
 *   - SLA tracking (red text if the incident is past its resolution deadline)
 *   - Manual incident creation via a Modal (requires linking an Alert ID
 *     because the backend mandates evidence for all incidents).
 *   - Pagination.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus, Clock } from "lucide-react";
import { toast } from "sonner";
import { isPast, isToday } from "date-fns";

import { api } from "@/lib/api";
import type {
  PaginatedResponse,
  SecurityIncident,
  IncidentStatus,
  IncidentSeverity,
} from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription, ModalFooter } from "@/components/ui/Modal";
import {
  TableWrapper,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/Table";
import { formatRelativeTime } from "@/lib/utils";


// ============================================================================
// TYPES & CONSTANTS
// ============================================================================

const STATUS_OPTIONS: IncidentStatus[] = [
  "open",
  "investigating",
  "containment",
  "eradication",
  "recovery",
  "resolved",
  "closed",
];

const SEVERITY_OPTIONS: IncidentSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
];


// ============================================================================
// SLA HELPER
// ============================================================================

function renderSLA(expiresAt: string | null) {
  if (!expiresAt) return <span className="text-slate-400">—</span>;
  
  const date = new Date(expiresAt);
  const isOverdue = isPast(date);
  const isDueSoon = isToday(date);

  return (
    <div className={`flex items-center gap-1.5 text-sm font-medium ${
      isOverdue ? "text-red-600 dark:text-red-400" : 
      isDueSoon ? "text-amber-600 dark:text-amber-400" : 
      "text-slate-600 dark:text-slate-400"
    }`}>
      <Clock size={14} />
      {isOverdue ? "Overdue" : formatRelativeTime(expiresAt)}
    </div>
  );
}


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Incidents() {
  const queryClient = useQueryClient();

  // ── State ─────────────────────────────────────────────────────────────
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<IncidentSeverity | "all">("all");
  const [isModalOpen, setIsModalOpen] = useState(false);

  // ── Data Fetching ─────────────────────────────────────────────────────
  const { data, isLoading, isError } = useQuery({
    queryKey: ["incidents", page, statusFilter, severityFilter],
    queryFn: async () => {
      const params: Record<string, any> = { page, page_size: 15 };
      if (statusFilter !== "all") params.status = statusFilter;
      if (severityFilter !== "all") params.severity = severityFilter;

      const { data } = await api.get<PaginatedResponse<SecurityIncident>>("/incidents", { params });
      return data;
    },
  });

  // ── RENDER ────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Incidents
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Manage investigations, coordinate containment, and track SLA compliance.
          </p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} leftIcon={<Plus size={16} />}>
          Create Incident
        </Button>
      </div>

      {/* ── Toolbar ────────────────────────────────────────────────────── */}
      <Card>
        <CardContent className="p-4 flex flex-col gap-4 sm:flex-row sm:items-center">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-500 dark:text-slate-400">Status:</span>
            <select
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value as any); setPage(1); }}
            >
              <option value="all">All</option>
              {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-500 dark:text-slate-400">Severity:</span>
            <select
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value as any); setPage(1); }}
            >
              <option value="all">All</option>
              {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
            </select>
          </div>
        </CardContent>
      </Card>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading incidents..." /></CardContent></Card>
      ) : isError ? (
        <Card><CardContent className="p-12 text-center text-red-500">Failed to load incidents.</CardContent></Card>
      ) : data?.items.length === 0 ? (
        <Card><CardContent className="p-12 text-center text-slate-500">No incidents found.</CardContent></Card>
      ) : (
        <>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">Severity</TableHead>
                  <TableHead>Incident</TableHead>
                  <TableHead className="hidden md:table-cell">Status</TableHead>
                  <TableHead className="hidden md:table-cell">SLA Deadline</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((incident) => (
                  <TableRow key={incident.id} interactive>
                    <TableCell>
                      <Badge severity={incident.severity} />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {incident.title}
                        </span>
                        <span className="text-xs text-slate-500">
                          {incident.occurrence_count} occurrence(s)
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <Badge status={incident.status} withDot />
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      {renderSLA(incident.expires_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Link to={`/incidents/${incident.id}`}>
                        <Button variant="ghost" size="sm">View</Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableWrapper>

          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" size="sm" onClick={() => setPage(p => p - 1)} disabled={!data?.meta.has_prev}>
              Previous
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={!data?.meta.has_next}>
              Next
            </Button>
          </div>
        </>
      )}

      {/* ── Create Modal ───────────────────────────────────────────────── */}
      <CreateIncidentModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={() => {
          setIsModalOpen(false);
          queryClient.invalidateQueries({ queryKey: ["incidents"] });
        }}
      />
    </div>
  );
}


// ============================================================================
// CREATE INCIDENT MODAL COMPONENT
// ============================================================================

function CreateIncidentModal({ isOpen, onClose, onSuccess }: { 
  isOpen: boolean; 
  onClose: () => void; 
  onSuccess: () => void; 
}) {
  const [alertId, setAlertId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<IncidentSeverity>("high");
  const [error, setError] = useState("");

  const mutation = useMutation({
    mutationFn: async (payload: any) => {
      const { data } = await api.post("/incidents", payload);
      return data;
    },
    onSuccess: () => {
      toast.success("Incident created successfully");
      onSuccess();
      resetForm();
    },
    onError: (err: any) => {
      setError(err.message || "Failed to create incident");
    },
  });

  const resetForm = () => {
    setAlertId("");
    setTitle("");
    setDescription("");
    setSeverity("high");
    setError("");
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!alertId) {
      setError("You must link an Alert ID to create an incident.");
      return;
    }
    if (!title) {
      setError("Title is required.");
      return;
    }

    mutation.mutate({
      title,
      description,
      severity,
      category: "other", // Defaulting for manual creation
      alert_ids: [alertId],
    });
  };

  return (
    <Modal open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <ModalContent>
        <form onSubmit={handleSubmit}>
          <ModalHeader>
            <ModalTitle>Create Incident</ModalTitle>
            <ModalDescription>
              Manually create an incident by linking an existing alert.
            </ModalDescription>
          </ModalHeader>

          <div className="space-y-4 py-4">
            {error && (
              <div className="rounded-md bg-red-50 p-3 text-sm text-red-600 dark:bg-red-900/30 dark:text-red-400">
                {error}
              </div>
            )}
            
            <Input
              label="Alert ID (UUID)"
              placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
              value={alertId}
              onChange={(e) => setAlertId(e.target.value)}
              required
            />

            <Input
              label="Incident Title"
              placeholder="Brief summary of the incident"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                Severity
              </label>
              <select
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
              >
                {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
              </select>
            </div>
          </div>

          <ModalFooter>
            <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
            <Button type="submit" isLoading={mutation.isPending}>Create Incident</Button>
          </ModalFooter>
        </form>
      </ModalContent>
    </Modal>
  );
}
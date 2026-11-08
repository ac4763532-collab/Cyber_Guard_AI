/**
 * CyberGuard AI — Reports Page
 * ============================================================================
 * 
 * Allows users to generate, view, and download security reports.
 * 
 * Features:
 *   - Lists generated reports (Daily, Incident, Custom).
 *   - Shows status (Generating vs Ready).
 *   - "Generate Report" modal to manually trigger a new PDF/CSV.
 *   - Secure file download (fetches the blob from the API with auth headers).
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, Download, Plus, AlertCircle, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription, ModalFooter } from "@/components/ui/Modal";
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";
import { formatDate, formatRelativeTime } from "@/lib/utils";


// ============================================================================
// LOCAL TYPES
// ============================================================================

interface SecurityReport {
  id: string;
  title: string;
  report_type: "daily" | "weekly" | "monthly" | "incident" | "custom";
  report_format: "pdf" | "csv" | "json";
  generation_status: "queued" | "generating" | "ready" | "failed";
  file_size_bytes: number | null;
  created_at: string;
  error_message: string | null;
}

const formatSize = (bytes: number | null) => {
  if (!bytes) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Reports() {
  const [isModalOpen, setIsModalOpen] = useState(false);

  // ── Fetch Reports ─────────────────────────────────────────────────────
  const { data, isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<SecurityReport>>("/reports", {
        params: { page: 1, page_size: 50 },
      });
      return data;
    },
    // Poll if any report is currently generating
    refetchInterval: (query) => {
      const reports = query.state.data?.items || [];
      const hasGenerating = reports.some(
        (r) => r.generation_status === "queued" || r.generation_status === "generating"
      );
      return hasGenerating ? 3000 : false;
    },
  });

  // ── Download Handler ──────────────────────────────────────────────────
  const handleDownload = async (report: SecurityReport) => {
    try {
      toast.info("Starting download...");
      
      // Fetch the file as a Blob using the Axios instance (so it carries the JWT)
      const response = await api.get(`/reports/${report.id}/download`, {
        responseType: "blob",
      });

      // Create a temporary URL for the Blob
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      
      // Set the filename
      const extension = report.report_format;
      const filename = `${report.title.replace(/[^a-z0-9]/gi, "_").toLowerCase()}.${extension}`;
      link.setAttribute("download", filename);
      
      document.body.appendChild(link);
      link.click();
      
      // Cleanup
      link.remove();
      window.URL.revokeObjectURL(url);
      
    } catch (error: any) {
      toast.error(error.message || "Failed to download report");
    }
  };

  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Reports
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Download scheduled summaries or generate custom investigation reports.
          </p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} leftIcon={<Plus size={16} />}>
          Generate Report
        </Button>
      </div>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading reports..." /></CardContent></Card>
      ) : data?.items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center p-12 text-center">
            <FileText size={48} className="text-slate-300 dark:text-slate-600 mb-4" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">No reports found</h3>
            <p className="mt-1 text-sm text-slate-500 max-w-sm">
              Reports are generated automatically at the end of each day, or you can generate one manually.
            </p>
          </CardContent>
        </Card>
      ) : (
        <TableWrapper>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Report Title</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Format</TableHead>
                <TableHead className="hidden md:table-cell">Date</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.items.map((report) => (
                <TableRow key={report.id}>
                  <TableCell>
                    <span className="font-medium text-slate-900 dark:text-slate-100">
                      {report.title}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" label={report.report_type} className="capitalize" />
                  </TableCell>
                  <TableCell className="uppercase text-xs font-semibold text-slate-500">
                    {report.report_format}
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-slate-500">
                    <div className="flex flex-col">
                      <span>{formatDate(report.created_at)}</span>
                      <span className="text-xs text-slate-400">{formatRelativeTime(report.created_at)}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    {report.generation_status === "ready" ? (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-green-600 dark:text-green-400">
                        <CheckCircle2 size={16} /> Ready ({formatSize(report.file_size_bytes)})
                      </div>
                    ) : report.generation_status === "failed" ? (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-red-600" title={report.error_message || ""}>
                        <AlertCircle size={16} /> Failed
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-amber-600 dark:text-amber-400">
                        <Spinner size="sm" /> Generating...
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={report.generation_status !== "ready"}
                      onClick={() => handleDownload(report)}
                      leftIcon={<Download size={14} />}
                    >
                      Download
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableWrapper>
      )}

      <GenerateReportModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </div>
  );
}


// ============================================================================
// GENERATE REPORT MODAL
// ============================================================================

function GenerateReportModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [title, setTitle] = useState("");
  const [reportType, setReportType] = useState("custom");
  const [format, setFormat] = useState("pdf");

  const mutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post("/reports", {
        title: title || "Custom Security Report",
        report_type: reportType,
        report_format: format,
        scope_type: "workspace",
        sections: [], // Default sections
      });
      return data;
    },
    onSuccess: () => {
      toast.success("Report generation started");
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      onClose();
      setTitle("");
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to request report");
    },
  });

  return (
    <Modal open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <ModalContent>
        <form onSubmit={(e) => { e.preventDefault(); mutation.mutate(); }}>
          <ModalHeader>
            <ModalTitle>Generate Report</ModalTitle>
            <ModalDescription>
              Create a custom report of your current security posture.
            </ModalDescription>
          </ModalHeader>

          <div className="py-6 space-y-4">
            <Input
              label="Report Title"
              placeholder="e.g. Q4 2026 Security Summary"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Report Type</label>
              <select
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
              >
                <option value="custom">Custom Summary</option>
                <option value="daily">Daily Snapshot</option>
                <option value="weekly">Weekly Summary</option>
                <option value="monthly">Monthly Overview</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Format</label>
              <select
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                value={format}
                onChange={(e) => setFormat(e.target.value)}
              >
                <option value="pdf">PDF Document</option>
                <option value="csv">CSV Spreadsheet</option>
              </select>
            </div>
          </div>

          <ModalFooter>
            <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
            <Button type="submit" isLoading={mutation.isPending}>Generate</Button>
          </ModalFooter>
        </form>
      </ModalContent>
    </Modal>
  );
}
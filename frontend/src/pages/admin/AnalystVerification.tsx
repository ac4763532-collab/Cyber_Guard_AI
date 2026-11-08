/**
 * CyberGuard AI — Admin: Analyst Verification Page
 * ============================================================================
 * 
 * The Super Admin's queue for reviewing new analyst applications.
 * 
 * Features:
 *   - Lists pending applications.
 *   - Detail Modal shows bio, specializations, certifications, and documents.
 *   - "Approve" instantly moves them to VERIFIED status.
 *   - "Reject" requires a written reason (which is emailed to the analyst).
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck, CheckCircle2, XCircle, FileText,
  ExternalLink, Award
} from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription, ModalFooter } from "@/components/ui/Modal";
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";
import { formatDate, formatRelativeTime } from "@/lib/utils";


// ============================================================================
// TYPES
// ============================================================================

interface AnalystApplication {
  id: string;
  user_id: string;
  display_name: string;
  email: string;
  headline: string | null;
  bio: string | null;
  specializations: string[];
  certifications: { name: string; issuer: string; year?: number }[];
  years_of_experience: number | null;
  hourly_rate_cents: number | null;
  verification_status: "pending" | "in_review";
  verification_submitted_at: string;
  verification_documents: { name: string; url: string }[];
}


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function AnalystVerification() {
  const [selectedAnalyst, setSelectedAnalyst] = useState<AnalystApplication | null>(null);

  // ── Fetch Pending Applications ────────────────────────────────────────
  const { data, isLoading } = useQuery({
    queryKey: ["pending-analysts"],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<AnalystApplication>>("/admin/analysts/pending", {
        params: { page: 1, page_size: 50 },
      });
      return data;
    },
  });

  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Analyst Verification
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Review credentials and approve new security experts for the marketplace.
        </p>
      </div>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading applications..." /></CardContent></Card>
      ) : data?.items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center p-12 text-center">
            <ShieldCheck size={48} className="text-green-500 mb-4" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">All caught up!</h3>
            <p className="mt-1 text-sm text-slate-500 max-w-sm">
              There are no pending analyst applications to review right now.
            </p>
          </CardContent>
        </Card>
      ) : (
        <TableWrapper>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Applicant</TableHead>
                <TableHead>Experience</TableHead>
                <TableHead>Certifications</TableHead>
                <TableHead className="hidden md:table-cell">Submitted</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.items.map((app) => (
                <TableRow key={app.id} interactive>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="font-medium text-slate-900 dark:text-slate-100">{app.display_name}</span>
                      <span className="text-xs text-slate-500">{app.email}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm">
                    {app.years_of_experience ? `${app.years_of_experience} years` : "Not specified"}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1 text-sm text-slate-600 dark:text-slate-400">
                      <Award size={14} className="text-amber-500" />
                      {app.certifications.length} certs
                    </div>
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-slate-500">
                    {formatRelativeTime(app.verification_submitted_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="secondary" size="sm" onClick={() => setSelectedAnalyst(app)}>
                      Review
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableWrapper>
      )}

      <ReviewAnalystModal 
        applicant={selectedAnalyst} 
        onClose={() => setSelectedAnalyst(null)} 
      />
    </div>
  );
}


// ============================================================================
// REVIEW MODAL
// ============================================================================

function ReviewAnalystModal({ applicant, onClose }: { 
  applicant: AnalystApplication | null; 
  onClose: () => void; 
}) {
  const queryClient = useQueryClient();
  const [isRejecting, setIsRejecting] = useState(false);
  const [rejectionReason, setRejectionReason] = useState("");

  // ── Approve Mutation ──────────────────────────────────────────────────
  const approveMutation = useMutation({
    mutationFn: async () => {
      if (!applicant) return;
      await api.post(`/admin/analysts/${applicant.id}/approve`, {
        notes: "Approved via admin dashboard.",
      });
    },
    onSuccess: () => {
      toast.success(`${applicant?.display_name} is now a verified analyst!`);
      queryClient.invalidateQueries({ queryKey: ["pending-analysts"] });
      onClose();
    },
    onError: (err: any) => toast.error(err.message || "Failed to approve"),
  });

  // ── Reject Mutation ───────────────────────────────────────────────────
  const rejectMutation = useMutation({
    mutationFn: async () => {
      if (!applicant) return;
      await api.post(`/admin/analysts/${applicant.id}/reject`, {
        reason: rejectionReason,
      });
    },
    onSuccess: () => {
      toast.success(`Application for ${applicant?.display_name} rejected.`);
      queryClient.invalidateQueries({ queryKey: ["pending-analysts"] });
      handleClose();
    },
    onError: (err: any) => toast.error(err.message || "Failed to reject"),
  });

  const handleClose = () => {
    setIsRejecting(false);
    setRejectionReason("");
    onClose();
  };

  if (!applicant) return null;

  return (
    <Modal open={!!applicant} onOpenChange={(open) => !open && handleClose()}>
      <ModalContent className="max-w-3xl">
        <ModalHeader>
          <ModalTitle>Review Application: {applicant.display_name}</ModalTitle>
          <ModalDescription>
            Submitted {formatDate(applicant.verification_submitted_at)}
          </ModalDescription>
        </ModalHeader>

        <div className="py-4 space-y-6 max-h-[60vh] overflow-y-auto pr-2">
          
          {/* Bio & Experience */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">Headline</h4>
              <p className="text-sm text-slate-600 dark:text-slate-400">{applicant.headline || "None"}</p>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">Experience</h4>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                {applicant.years_of_experience ? `${applicant.years_of_experience} years` : "Unknown"}
              </p>
            </div>
          </div>

          <div>
            <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">Bio</h4>
            <p className="text-sm text-slate-600 dark:text-slate-400 whitespace-pre-wrap">
              {applicant.bio || "No bio provided."}
            </p>
          </div>

          {/* Specializations */}
          <div>
            <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-2">Specializations</h4>
            <div className="flex flex-wrap gap-2">
              {applicant.specializations.map((s) => (
                <Badge key={s} variant="outline" label={s.replace("_", " ")} />
              ))}
            </div>
          </div>

          {/* Certifications */}
          <div>
            <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-2">Certifications</h4>
            <ul className="space-y-2">
              {applicant.certifications.map((cert, i) => (
                <li key={i} className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 bg-slate-50 p-2 rounded-md dark:bg-slate-800/50">
                  <Award size={16} className="text-brand-500" />
                  <span className="font-medium">{cert.name}</span>
                  <span className="text-slate-400">•</span>
                  <span>{cert.issuer}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Documents */}
          <div>
            <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-2">Uploaded Documents</h4>
            <div className="grid grid-cols-2 gap-2">
              {applicant.verification_documents.map((doc, i) => (
                <a 
                  key={i} 
                  href={doc.url} 
                  target="_blank" 
                  rel="noreferrer"
                  className="flex items-center gap-2 p-3 border border-slate-200 rounded-lg hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800 transition-colors"
                >
                  <FileText size={16} className="text-slate-400" />
                  <span className="text-sm truncate">{doc.name}</span>
                  <ExternalLink size={12} className="ml-auto text-slate-400" />
                </a>
              ))}
            </div>
          </div>

          {/* Rejection Form */}
          {isRejecting && (
            <div className="rounded-lg bg-red-50 p-4 border border-red-200 dark:bg-red-900/20 dark:border-red-800 space-y-2">
              <label className="text-sm font-medium text-red-800 dark:text-red-300">
                Rejection Reason (required)
              </label>
              <textarea
                className="w-full rounded-md border border-red-300 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-red-500 dark:border-red-700 dark:bg-slate-900"
                rows={3}
                placeholder="Explain why the application is being rejected..."
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
              />
            </div>
          )}

        </div>

        <ModalFooter className="mt-2">
          {isRejecting ? (
            <>
              <Button variant="ghost" onClick={() => setIsRejecting(false)}>Cancel</Button>
              <Button 
                variant="danger" 
                onClick={() => rejectMutation.mutate()} 
                isLoading={rejectMutation.isPending}
                disabled={!rejectionReason.trim()}
              >
                Confirm Rejection
              </Button>
            </>
          ) : (
            <>
              <Button variant="ghost" onClick={handleClose}>Close</Button>
              <Button 
                variant="outline" 
                className="text-red-600 border-red-200 hover:bg-red-50 dark:border-red-900 dark:hover:bg-red-900/20"
                onClick={() => setIsRejecting(true)}
                leftIcon={<XCircle size={16} />}
              >
                Reject
              </Button>
              <Button 
                variant="primary" 
                onClick={() => approveMutation.mutate()} 
                isLoading={approveMutation.isPending}
                leftIcon={<CheckCircle2 size={16} />}
              >
                Approve Analyst
              </Button>
            </>
          )}
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
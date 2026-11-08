/**
 * CyberGuard AI — Page 29: Evidence Library
 * ============================================================================
 * Browse and verify forensic evidence artifacts strictly for authorized and
 * assigned cases. Preserves SHA-256 hashes, chain of custody, and provenance.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Database, ShieldCheck, Download, Search, Lock, FileCode, CheckCircle2, AlertCircle, Inbox } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";

interface EvidenceItem {
  id: string;
  case_id: string;
  original_filename: string;
  evidence_type: string;
  mime_type: string;
  file_size_bytes: number;
  content_hash: string;
  integrity_verified: boolean;
  created_at: string;
  description: string | null;
}

export default function EvidenceLibrary() {
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState("");

  const { data, isLoading } = useQuery<{ items: EvidenceItem[]; total: number }>({
    queryKey: ["analyst-evidence"],
    queryFn: async () => {
      const { data } = await api.get<{ items: EvidenceItem[]; total: number }>("/evidence");
      return data;
    },
  });

  const verifyMutation = useMutation({
    mutationFn: async (evidenceId: string) => {
      const { data } = await api.post(`/evidence/${evidenceId}/verify`, {
        notes: "Analyst cryptographic re-verification from vault UI",
      });
      return data;
    },
    onSuccess: (res: any) => {
      if (res.integrity_verified) {
        toast.success("Cryptographic SHA-256 integrity verified! Hash matches disk payload.");
      } else {
        toast.error("Integrity check FAILED: Hash mismatch or file compromised.");
      }
      queryClient.invalidateQueries({ queryKey: ["analyst-evidence"] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Verification request failed");
    },
  });

  const handleDownload = (id: string, filename: string) => {
    const url = `/api/v1/evidence/${id}/download`;
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    toast.info(`Downloading ${filename}`);
  };

  const filtered = (data?.items || []).filter((art) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      art.original_filename.toLowerCase().includes(term) ||
      art.content_hash.toLowerCase().includes(term) ||
      art.evidence_type.toLowerCase().includes(term)
    );
  });

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 29 • Evidence Vault
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Forensic Evidence Vault
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Tamper-evident chain of custody records with cryptographic SHA-256 verification.
          </p>
        </div>
      </div>

      <div className="w-full max-w-md">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter by filename, hash, type..."
          className="bg-slate-900 border-slate-800 text-xs"
        />
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-3 border-b border-slate-800/80">
          <CardTitle className="text-base text-slate-100">Case-Authorized Artifacts</CardTitle>
        </CardHeader>
        <CardContent className="p-0 divide-y divide-slate-800/80">
          {isLoading ? (
            <div className="p-12 text-center">
              <Spinner label="Loading vault evidence..." />
            </div>
          ) : filtered.length === 0 ? (
            <div className="p-12 text-center text-slate-400">
              <Inbox size={48} className="mx-auto text-slate-600 mb-3" />
              <h3 className="text-base font-bold text-slate-200">No forensic evidence found</h3>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                No artifacts have been attached to your assigned cases yet. When email or network captures are linked, they will appear here with cryptographic hashes.
              </p>
            </div>
          ) : (
            filtered.map((art) => (
              <div key={art.id} className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-800/30 transition">
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      Case: {art.case_id.substring(0, 8)}...
                    </span>
                    <span className="font-semibold text-sm text-slate-200">{art.original_filename}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                      {formatBytes(art.file_size_bytes)}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-mono uppercase">
                      {art.evidence_type}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono break-all">
                    SHA-256: <span className="text-emerald-400">{art.content_hash}</span>
                  </p>
                  <p className="text-[11px] text-slate-500">
                    Recorded {formatRelativeTime(art.created_at)} • MIME: {art.mime_type}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => verifyMutation.mutate(art.id)}
                    isLoading={verifyMutation.isPending}
                    className="border-slate-800 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    <CheckCircle2 size={14} className="mr-1.5 text-emerald-400" /> Verify Hash
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => handleDownload(art.id, art.original_filename)}
                    className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
                  >
                    <Download size={14} className="mr-1.5" /> Download
                  </Button>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}

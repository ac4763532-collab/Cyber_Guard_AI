/**
 * CyberGuard AI — Page 08: Gmail Inbox & Email Security
 * ============================================================================
 * Live email defense: Gmail OAuth synchronization, RFC 822 .eml analysis,
 * phishing heuristics, DMARC/SPF verification, and interactive email inbox reader.
 */

import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { 
  Mail, 
  Upload, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Search, 
  ExternalLink,
  RefreshCw,
  Inbox,
  ShieldCheck,
  Paperclip,
  CheckCircle2,
  Clock,
  X,
  Eye,
  Lock,
  Cpu,
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { api } from "@/lib/api";

interface EmailItem {
  id: string;
  sender: string;
  recipient?: string;
  subject: string;
  snippet?: string;
  received_at: string;
  verdict: "phishing" | "suspicious" | "clean";
  score: number;
  status: string;
  source: string;
  has_attachments?: boolean;
}

interface GmailStatus {
  configured: boolean;
  connected: boolean;
  email_address?: string | null;
  last_sync_at?: string | null;
  auth_url?: string;
}

export default function EmailSecurity() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedFilter, setSelectedFilter] = useState<"all" | "phishing" | "suspicious" | "clean">("all");
  const [isUploading, setIsUploading] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState<EmailItem | null>(null);

  // Check Gmail connection status
  const { data: gmailStatus, refetch: refetchGmailStatus } = useQuery<GmailStatus>({
    queryKey: ["gmail-status"],
    queryFn: async () => {
      const { data } = await api.get<GmailStatus>("/email/gmail/status");
      return data;
    },
  });

  // Live emails list from PostgreSQL
  const { data: emails = [], isLoading, refetch, isFetching } = useQuery<EmailItem[]>({
    queryKey: ["email-analyses"],
    queryFn: async () => {
      const { data } = await api.get<EmailItem[]>("/email/messages");
      return data || [];
    },
  });

  // Trigger Gmail Sync mutation
  const syncMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post("/email/gmail/sync");
      return data;
    },
    onSuccess: (data: any) => {
      toast.success(data?.message || "Gmail inbox synchronized successfully.");
      refetch();
      refetchGmailStatus();
    },
    onError: (err: any) => {
      const msg =
        err.response?.data?.detail ||
        err.response?.data?.error?.message ||
        "Failed to sync Gmail inbox. Please verify your connection.";
      toast.error(msg);
      refetchGmailStatus();
    },
  });

  // Handle URL redirect params from OAuth callback
  useEffect(() => {
    const connected = searchParams.get("connected");
    const email = searchParams.get("email");
    const error = searchParams.get("error");

    if (connected === "true") {
      toast.success(`Gmail account connected successfully! (${email || ""})`);
      window.history.replaceState({}, document.title, window.location.pathname);
      refetchGmailStatus();
      refetch();
    } else if (error) {
      toast.error(`Gmail connection error: ${decodeURIComponent(error)}`);
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [searchParams, refetchGmailStatus, refetch]);

  const handleConnectGmail = async () => {
    try {
      const { data } = await api.get("/email/gmail/auth-url");
      if (data?.auth_url) {
        window.location.href = data.auth_url;
      }
    } catch (err: any) {
      const errorMsg =
        err.response?.data?.error?.message ||
        err.response?.data?.detail ||
        "Gmail integration not configured. Provide Google OAuth credentials in backend .env to enable synchronization.";
      toast.error(errorMsg);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const { data } = await api.post("/email/uploads", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      toast.success(`EML analyzed: Verdict is ${data.verdict.toUpperCase()} (Score: ${data.score}%)`);
      refetch();
      if (data?.analysis_id) {
        navigate(`/personal/email/${data.analysis_id}`);
      }
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to parse EML file. Ensure it is a valid RFC 822 formatted email.");
    } finally {
      setIsUploading(false);
      e.target.value = "";
    }
  };

  const phishingCount = emails.filter((e) => e.verdict === "phishing").length;
  const suspiciousCount = emails.filter((e) => e.verdict === "suspicious").length;
  const cleanCount = emails.filter((e) => e.verdict === "clean").length;

  const filtered = emails.filter((e) => {
    if (selectedFilter !== "all" && e.verdict !== selectedFilter) {
      return false;
    }
    return (
      e.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.snippet && e.snippet.toLowerCase().includes(searchTerm.toLowerCase()))
    );
  });

  const formatDate = (dateStr: string) => {
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 08 • Email Defense
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2 flex items-center gap-3">
            <Mail className="w-8 h-8 text-cyan-400" />
            Gmail Inbox & Email Security
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time mailbox defense: inspect headers, detect spear-phishing, spoofed senders, and malicious links.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="border-slate-800 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw size={14} className={`mr-1.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>

          {gmailStatus?.connected ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
              className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-xs font-semibold"
            >
              <RefreshCw size={14} className={`mr-1.5 ${syncMutation.isPending ? "animate-spin" : ""}`} />
              {syncMutation.isPending ? "Syncing Inbox..." : "Sync Gmail Inbox"}
            </Button>
          ) : (
            <Button
              variant="outline"
              size="sm"
              onClick={handleConnectGmail}
              className="border-rose-500/30 hover:bg-rose-500/10 text-rose-300 text-xs font-semibold"
            >
              <Mail size={14} className="mr-1.5 text-rose-400" /> Connect Gmail Account
            </Button>
          )}

          <label className="cursor-pointer">
            <input
              type="file"
              accept=".eml,.msg,message/rfc822"
              className="hidden"
              onChange={handleFileUpload}
              disabled={isUploading}
            />
            <span className="inline-flex items-center justify-center rounded-xl font-bold transition-colors focus-visible:outline-none px-4 py-2 text-xs bg-cyan-500 hover:bg-cyan-400 text-slate-950">
              <Upload size={14} className="mr-1.5" />
              {isUploading ? "Analyzing..." : "Upload .EML"}
            </span>
          </label>
        </div>
      </div>

      {/* ML Intelligence Banner */}
      <div className="p-3.5 bg-slate-900 border border-cyan-500/30 rounded-2xl flex items-center justify-between text-xs shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
            <Cpu size={16} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100">Machine Learning Threat Engine</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 uppercase tracking-wide flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Live ML Active
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Powered by <span className="text-slate-200 font-mono">scikit-learn 1.5.2</span> • Supervised TF-IDF NLP Phishing Classifier &amp; Isolation Forest Anomaly Detection
            </p>
          </div>
        </div>
        <div className="hidden sm:flex items-center gap-2">
          <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-1 rounded-lg">
            In-Process &lt;50ms
          </span>
        </div>
      </div>

      {/* Gmail Connection Status Banner */}
      {gmailStatus?.connected ? (
        <div className="p-4 bg-slate-900 border border-emerald-500/30 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
              <CheckCircle2 size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-slate-100">Gmail Connected</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 uppercase tracking-wide">
                  Live Monitoring
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                {gmailStatus.email_address}
                {gmailStatus.last_sync_at && (
                  <span className="text-slate-500 ml-2 font-sans">
                    • Last synced: {new Date(gmailStatus.last_sync_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                )}
              </p>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
          >
            <RefreshCw size={13} className={`mr-1.5 ${syncMutation.isPending ? "animate-spin" : ""}`} />
            {syncMutation.isPending ? "Syncing..." : "Sync Inbox Messages"}
          </Button>
        </div>
      ) : (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 shrink-0">
              <Mail size={22} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-200">Connect Gmail for Continuous Inbox Protection</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Automatically fetch, analyze, and quarantine phishing emails from your Gmail inbox using AI defense.
              </p>
            </div>
          </div>
          <Button
            onClick={handleConnectGmail}
            className="bg-gradient-to-r from-rose-500 to-rose-600 hover:from-rose-600 hover:to-rose-700 text-white font-bold text-xs shadow-md shadow-rose-500/20 shrink-0"
          >
            <Mail size={14} className="mr-1.5" /> Connect with Google
          </Button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Total Inbox Emails</p>
          <p className="text-2xl font-black text-slate-100 mt-1">{emails.length}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Phishing Detected</p>
          <p className="text-2xl font-black text-rose-400 mt-1">{phishingCount}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Suspicious Flagged</p>
          <p className="text-2xl font-black text-amber-400 mt-1">{suspiciousCount}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Clean & Verified</p>
          <p className="text-2xl font-black text-emerald-400 mt-1">{cleanCount}</p>
        </Card>
      </div>

      {/* Main Inbox Card */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-3 border-b border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Filter Tabs */}
          <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800">
            <button
              type="button"
              onClick={() => setSelectedFilter("all")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                selectedFilter === "all"
                  ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Inbox size={14} />
              All Inbox ({emails.length})
            </button>
            <button
              type="button"
              onClick={() => setSelectedFilter("phishing")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                selectedFilter === "phishing"
                  ? "bg-rose-500 text-slate-950 shadow-md shadow-rose-500/20"
                  : "text-slate-400 hover:text-rose-400"
              }`}
            >
              <ShieldAlert size={14} />
              Phishing ({phishingCount})
            </button>
            <button
              type="button"
              onClick={() => setSelectedFilter("suspicious")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                selectedFilter === "suspicious"
                  ? "bg-amber-500 text-slate-950 shadow-md shadow-amber-500/20"
                  : "text-slate-400 hover:text-amber-400"
              }`}
            >
              <AlertTriangle size={14} />
              Suspicious ({suspiciousCount})
            </button>
            <button
              type="button"
              onClick={() => setSelectedFilter("clean")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                selectedFilter === "clean"
                  ? "bg-emerald-500 text-slate-950 shadow-md shadow-emerald-500/20"
                  : "text-slate-400 hover:text-emerald-400"
              }`}
            >
              <ShieldCheck size={14} />
              Clean ({cleanCount})
            </button>
          </div>

          {/* Search Box */}
          <div className="w-full md:w-72">
            <Input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search sender, subject..."
              className="bg-slate-950 border-slate-800 text-xs h-9 text-slate-200"
            />
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center text-sm text-slate-400 flex flex-col items-center justify-center gap-2">
              <RefreshCw size={24} className="animate-spin text-cyan-400" />
              <span>Loading analyzed inbox messages...</span>
            </div>
          ) : filtered.length === 0 ? (
            <div className="p-14 text-center border-t border-slate-800/80">
              <Inbox className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="text-base font-bold text-slate-200">No emails found in this view</p>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                {gmailStatus?.connected
                  ? "Your Gmail is connected. Click 'Sync Gmail Inbox' above to pull and analyze your latest emails."
                  : "Connect your Gmail account or upload an authorized .eml file to inspect email headers and detect phishing."}
              </p>
              {!gmailStatus?.connected && (
                <Button
                  onClick={handleConnectGmail}
                  className="mt-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold"
                >
                  <Mail size={14} className="mr-1.5" /> Connect Gmail Now
                </Button>
              )}
            </div>
          ) : (
            <div className="divide-y divide-slate-800/70">
              {filtered.map((item) => (
                <div
                  key={item.id}
                  onClick={() => setSelectedEmail(item)}
                  className="p-4 hover:bg-slate-800/50 transition cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 group"
                >
                  <div className="flex items-start gap-3.5 max-w-3xl">
                    <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700/60 flex items-center justify-center text-slate-300 font-bold text-sm shrink-0 uppercase group-hover:border-cyan-500/50 transition-colors">
                      {item.sender.charAt(0)}
                    </div>
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-sm text-slate-100 group-hover:text-cyan-400 transition-colors">
                          {item.sender}
                        </span>
                        {item.verdict === "phishing" ? (
                          <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                            Phishing Detected ({item.score}%)
                          </span>
                        ) : item.verdict === "suspicious" ? (
                          <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            Suspicious ({item.score}%)
                          </span>
                        ) : (
                          <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            Clean & Safe
                          </span>
                        )}
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          {item.source === "gmail" ? "Gmail Sync" : "EML Upload"}
                        </span>
                      </div>

                      <h4 className="text-xs font-medium text-slate-200">
                        {item.subject}
                      </h4>

                      {item.snippet && (
                        <p className="text-xs text-slate-400 line-clamp-1">
                          {item.snippet}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                    <span className="text-xs text-slate-400 flex items-center gap-1">
                      <Clock size={12} /> {formatDate(item.received_at)}
                    </span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/personal/email/${item.id}`);
                      }}
                      className="border-slate-800 hover:border-cyan-500/40 text-xs text-cyan-400 hover:bg-cyan-500/10 font-semibold"
                    >
                      <Eye size={13} className="mr-1" /> Forensic Analysis
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Interactive Email Reader Modal */}
      {selectedEmail && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-2">
                <Mail className="text-cyan-400" size={18} />
                <h3 className="text-sm font-bold text-slate-100">Inbox Message Preview</h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEmail(null)}
                className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition"
              >
                <X size={16} />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-4">
              {/* Verdict Banner */}
              <div
                className={`p-4 rounded-xl border flex items-center justify-between ${
                  selectedEmail.verdict === "phishing"
                    ? "bg-rose-500/10 border-rose-500/30 text-rose-300"
                    : selectedEmail.verdict === "suspicious"
                    ? "bg-amber-500/10 border-amber-500/30 text-amber-300"
                    : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                }`}
              >
                <div className="flex items-center gap-3">
                  {selectedEmail.verdict === "phishing" ? (
                    <ShieldAlert size={22} className="text-rose-400" />
                  ) : selectedEmail.verdict === "suspicious" ? (
                    <AlertTriangle size={22} className="text-amber-400" />
                  ) : (
                    <ShieldCheck size={22} className="text-emerald-400" />
                  )}
                  <div>
                    <h4 className="font-bold text-sm">
                      {selectedEmail.verdict === "phishing"
                        ? "Phishing Threat Flagged"
                        : selectedEmail.verdict === "suspicious"
                        ? "Suspicious Email Characteristics"
                        : "Verified Clean Email"}
                    </h4>
                    <p className="text-xs opacity-90 mt-0.5">
                      Security Confidence Score: {selectedEmail.score}% risk level
                    </p>
                  </div>
                </div>
              </div>

              {/* Message Metadata */}
              <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                <div>
                  <span className="text-slate-400">Subject:</span>{" "}
                  <span className="font-bold text-slate-100">{selectedEmail.subject}</span>
                </div>
                <div>
                  <span className="text-slate-400">From:</span>{" "}
                  <span className="font-mono text-cyan-300">{selectedEmail.sender}</span>
                </div>
                {selectedEmail.recipient && (
                  <div>
                    <span className="text-slate-400">To:</span>{" "}
                    <span className="font-mono text-slate-300">{selectedEmail.recipient}</span>
                  </div>
                )}
                <div>
                  <span className="text-slate-400">Received:</span>{" "}
                  <span className="text-slate-300">{formatDate(selectedEmail.received_at)}</span>
                </div>
              </div>

              {/* Body Snippet */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Message Body Preview</h4>
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed max-h-56 overflow-y-auto">
                  {selectedEmail.snippet || "Full email payload content available in deep forensic inspection."}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedEmail(null)}
                className="border-slate-800 text-slate-300 text-xs"
              >
                Close Preview
              </Button>

              <Button
                size="sm"
                onClick={() => {
                  const id = selectedEmail.id;
                  setSelectedEmail(null);
                  navigate(`/personal/email/${id}`);
                }}
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
              >
                Inspect Forensic Details <ExternalLink size={13} className="ml-1.5" />
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

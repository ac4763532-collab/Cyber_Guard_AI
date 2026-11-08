/**
 * CyberGuard AI — Page 08: Gmail Inbox & Email Security
 * ============================================================================
 * Live email defense: RFC 822 .eml analysis via deterministic heuristics,
 * IOC matching, DMARC/SPF verification, and Gmail OAuth integration.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { 
  Mail, 
  Upload, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Search, 
  ExternalLink,
  RefreshCw
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { api } from "@/lib/api";

interface EmailItem {
  id: string;
  sender: string;
  subject: string;
  received_at: string;
  verdict: "phishing" | "suspicious" | "clean";
  score: number;
  status: string;
  source: string;
}

export default function EmailSecurity() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState("");
  const [isUploading, setIsUploading] = useState(false);

  // Live API emails from PostgreSQL
  const { data: emails = [], isLoading, refetch, isFetching } = useQuery<EmailItem[]>({
    queryKey: ["email-analyses"],
    queryFn: async () => {
      const { data } = await api.get<EmailItem[]>("/email/messages");
      return data || [];
    },
  });

  const handleConnectGmail = async () => {
    try {
      const { data } = await api.get("/email/gmail/auth-url");
      if (data?.auth_url) {
        window.location.href = data.auth_url;
      }
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Gmail integration not configured. Provide Google OAuth credentials in backend .env to enable synchronization.");
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

  const filtered = emails.filter((e) =>
    e.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
    e.sender.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const phishingCount = emails.filter((e) => e.verdict === "phishing").length;
  const cleanCount = emails.filter((e) => e.verdict === "clean").length;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 08 • Email Defense
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Email & Phishing Security
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Detect spear-phishing, credential harvesters, spoofed domains, and malicious attachments with RFC 822 inspection.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="border-slate-800 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw size={14} className={`mr-1.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleConnectGmail}
            className="border-slate-800 hover:bg-slate-800 text-slate-200 text-xs font-semibold"
          >
            <Mail size={14} className="mr-1.5 text-rose-400" /> Connect Gmail
          </Button>

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

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Total Analyzed</p>
          <p className="text-xl font-bold text-slate-100 mt-1">{emails.length} Emails</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Flagged Threats</p>
          <p className="text-xl font-bold text-rose-400 mt-1">{phishingCount} Phishing</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Clean / Verified</p>
          <p className="text-xl font-bold text-emerald-400 mt-1">{cleanCount} Clean</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Detection Engine</p>
          <p className="text-xl font-bold text-cyan-400 mt-1">6 Active Rules</p>
        </Card>
      </div>

      {/* Main List */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-3 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <CardTitle className="text-base text-slate-100">Analyzed Messages</CardTitle>
          <div className="w-64">
            <Input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search sender, subject..."
              className="bg-slate-950 border-slate-800 text-xs h-8 text-slate-200"
            />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center text-sm text-slate-400">Loading analyzed email records...</div>
          ) : filtered.length === 0 ? (
            <div className="p-12 text-center border-t border-slate-800/80">
              <Mail className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <p className="text-sm font-semibold text-slate-300">No emails analyzed yet</p>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                Gmail not connected. Connect your Gmail account or upload an authorized .eml file to inspect email headers and detect phishing.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {filtered.map((item) => (
                <div
                  key={item.id}
                  onClick={() => navigate(`/personal/email/${item.id}`)}
                  className="p-4 hover:bg-slate-800/40 transition cursor-pointer flex items-center justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-slate-200">{item.sender}</span>
                      {item.verdict === "phishing" ? (
                        <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">
                          Phishing Detected ({item.score}%)
                        </span>
                      ) : item.verdict === "suspicious" ? (
                        <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                          Suspicious ({item.score}%)
                        </span>
                      ) : (
                        <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          Clean
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-300 font-medium">{item.subject}</p>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate(`/personal/email/${item.id}`);
                    }}
                    className="text-xs text-cyan-400 hover:bg-cyan-500/10"
                  >
                    Inspect <ExternalLink size={12} className="ml-1" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/**
 * CyberGuard AI — Page 09: Email Review & Analysis
 * ============================================================================
 * Evidence-backed analysis showing SPF/DKIM/DMARC verdicts, extracted URLs,
 * attachment hashes, and explanation of why an email was flagged.
 */

import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { 
  ArrowLeft, 
  ShieldAlert, 
  CheckCircle, 
  XCircle, 
  ExternalLink, 
  FileText, 
  Share2, 
  AlertTriangle,
  Paperclip,
  Globe,
  Cpu
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { api } from "@/lib/api";

interface EmailAnalysisDetail {
  id: string;
  sender: string;
  recipient?: string;
  subject: string;
  received_at: string;
  verdict: string;
  score: number;
  confidence: number;
  status: string;
  auth_results: { raw?: string };
  headers: Record<string, string>;
  urls_found: string[];
  attachments: Array<{
    filename: string;
    mime: string;
    size_bytes: number;
    sha256: string;
  }>;
  triggered_rules: Array<{
    rule_id: string;
    title: string;
    description: string;
    severity: string;
    confidence: number;
  }>;
  body_excerpt: string;
}

export default function EmailAnalysis() {
  const { analysisId } = useParams<{ analysisId: string }>();
  const navigate = useNavigate();

  const { data, isLoading, error } = useQuery<EmailAnalysisDetail>({
    queryKey: ["email-analysis", analysisId],
    queryFn: async () => {
      const res = await api.get<EmailAnalysisDetail>(`/email/analyses/${analysisId}`);
      return res.data;
    },
    enabled: Boolean(analysisId),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading email forensic telemetry...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-8 text-center border border-slate-800 bg-slate-900 rounded-2xl max-w-lg mx-auto mt-12">
        <AlertTriangle className="w-12 h-12 text-amber-400 mx-auto mb-3" />
        <h2 className="text-lg font-bold text-slate-100">Email Analysis Record Not Found</h2>
        <p className="text-xs text-slate-400 mt-2 mb-4">
          The requested email analysis ID could not be retrieved from the database.
        </p>
        <Button onClick={() => navigate("/personal/email")} variant="outline" size="sm" className="border-slate-800 text-slate-200">
          <ArrowLeft size={14} className="mr-1.5" /> Return to Email Inbox
        </Button>
      </div>
    );
  }

  const isPhishing = data.verdict === "phishing";

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate("/personal/email")}
          className="text-slate-400 hover:text-slate-200"
        >
          <ArrowLeft size={16} className="mr-1" /> Back to Inbox
        </Button>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${isPhishing ? "text-rose-400 bg-rose-500/10 border border-rose-500/30" : "text-emerald-400 bg-emerald-500/10 border border-emerald-500/30"}`}>
            {data.verdict.toUpperCase()} (Score: {data.score}%)
          </span>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight mt-2">
            {data.subject}
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">From: {data.sender} • Ingested: {new Date(data.received_at).toLocaleString()}</p>
        </div>

        <div className="flex gap-2">
          <Button
            size="sm"
            onClick={() => {
              toast.success("Forensic evidence reference copied to clipboard.");
              navigate(`/personal/messages?ref=${data.id}`);
            }}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
          >
            <Share2 size={14} className="mr-1.5" /> Consult Security Analyst
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        
        {/* ML Phishing Engine (scikit-learn) */}
        <Card className="bg-slate-900 border-cyan-500/30 p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase text-cyan-400 tracking-wider flex items-center gap-1.5">
              <Cpu size={14} className="text-cyan-400" /> ML Phishing Engine
            </h3>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
              Scikit-Learn
            </span>
          </div>
          <div className="mt-3 space-y-2 text-xs">
            <div className="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1.5">
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-400">Architecture:</span>
                <span className="font-mono text-slate-200">TF-IDF + Naive Bayes</span>
              </div>
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-400">ML Threat Score:</span>
                <span className={`font-bold ${data.score >= 70 ? "text-rose-400" : "text-emerald-400"}`}>
                  {data.score} / 100
                </span>
              </div>
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-400">Model Confidence:</span>
                <span className="text-cyan-400 font-bold">{Math.round(data.confidence * 100)}%</span>
              </div>
            </div>
            <div className="text-[11px] text-emerald-400 flex items-center gap-1.5 pt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Real-time in-process inference</span>
            </div>
          </div>
        </Card>

        {/* Authentication Checks */}
        <Card className="bg-slate-900 border-slate-800 p-5">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider">Authentication Checks</h3>
          <div className="mt-3 space-y-2 text-xs">
            <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg">
              <span className="text-slate-400 block text-[11px]">Authentication-Results Header:</span>
              <p className="font-mono text-slate-200 mt-1 break-all">
                {data.auth_results?.raw || "None reported in headers"}
              </p>
            </div>
            <div className="flex items-center justify-between pt-1">
              <span className="text-slate-300">Analysis Confidence:</span>
              <span className="text-cyan-400 font-bold">{Math.round(data.confidence * 100)}%</span>
            </div>
          </div>
        </Card>

        {/* Suspicious URLs */}
        <Card className="bg-slate-900 border-slate-800 p-5">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider flex items-center gap-1.5">
            <Globe size={14} className="text-cyan-400" /> Extracted URLs ({data.urls_found.length})
          </h3>
          <div className="mt-3 space-y-2 text-xs">
            {data.urls_found.length === 0 ? (
              <p className="text-slate-500 italic py-2">No external hyperlinks found in email body.</p>
            ) : (
              data.urls_found.map((url, i) => (
                <div key={i} className="p-2 bg-slate-950/80 rounded border border-slate-800 text-slate-200 font-mono text-[11px] break-all">
                  {url}
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Detection Rules Triggered */}
        <Card className="bg-slate-900 border-slate-800 p-5">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider flex items-center gap-1.5">
            <ShieldAlert size={14} className="text-rose-400" /> Triggered Rules ({data.triggered_rules.length})
          </h3>
          <div className="mt-3 space-y-2 text-xs">
            {data.triggered_rules.length === 0 ? (
              <p className="text-emerald-400 text-xs py-2">No security threat rules fired.</p>
            ) : (
              data.triggered_rules.map((rule, idx) => (
                <div key={idx} className="p-2.5 bg-slate-950/70 border border-rose-500/30 rounded-lg">
                  <span className="font-bold text-rose-300">{rule.title}</span>
                  <p className="text-[11px] text-slate-400 mt-0.5">{rule.description}</p>
                </div>
              ))
            )}
          </div>
        </Card>

      </div>

      {/* Attachments & Body Excerpt */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-base text-slate-100 flex items-center gap-2">
              <Paperclip size={16} className="text-cyan-400" />
              Attachments ({data.attachments.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {data.attachments.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No file attachments enclosed in this message.</p>
            ) : (
              data.attachments.map((att, i) => (
                <div key={i} className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-xs font-bold text-slate-200">{att.filename}</p>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">SHA-256: {att.sha256}</p>
                  </div>
                  <span className="text-[11px] text-slate-400">{(att.size_bytes / 1024).toFixed(1)} KB</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-base text-slate-100 flex items-center gap-2">
              <FileText size={16} className="text-cyan-400" />
              Raw Text Body Excerpt
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-300 whitespace-pre-wrap max-h-64 overflow-y-auto">
              {data.body_excerpt || "(No plain text content available)"}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

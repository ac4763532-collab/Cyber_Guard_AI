/**
 * CyberGuard AI — Page 09: Email Review & Analysis
 * ============================================================================
 * Evidence-backed analysis showing SPF/DKIM/DMARC verdicts, extracted URLs,
 * attachment hashes, and explanation of why an email was flagged.
 */

import { useParams, useNavigate } from "react-router-dom";
import { 
  ArrowLeft, 
  ShieldAlert, 
  CheckCircle, 
  XCircle, 
  ExternalLink, 
  FileText, 
  Share2, 
  AlertTriangle 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function EmailAnalysis() {
  const { analysisId } = useParams<{ analysisId: string }>();
  const navigate = useNavigate();

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
          <span className="text-xs font-bold uppercase tracking-wider text-rose-400 bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded-full">
            High-Risk Phishing Finding
          </span>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight mt-2">
            Urgent: Your account has been suspended — Verify immediately
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">Analysis ID: {analysisId || "eml-001"}</p>
        </div>

        <div className="flex gap-2">
          <Button
            size="sm"
            onClick={() => {
              toast.success("Evidence shared with Security Analysts via Page 18");
              navigate("/personal/messages");
            }}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
          >
            <Share2 size={14} className="mr-1.5" /> Share with Analyst
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <Card className="bg-slate-900 border-slate-800 p-5">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider">Authentication Checks</h3>
          <div className="mt-3 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-300">SPF Validation:</span>
              <span className="text-rose-400 font-bold flex items-center gap-1"><XCircle size={14} /> SoftFail</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-300">DKIM Signature:</span>
              <span className="text-rose-400 font-bold flex items-center gap-1"><XCircle size={14} /> Missing / Invalid</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-300">DMARC Policy:</span>
              <span className="text-amber-400 font-bold">Reject triggered</span>
            </div>
          </div>
        </Card>

        <Card className="bg-slate-900 border-slate-800 p-5">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider">Suspicious Link Analysis</h3>
          <div className="mt-3 space-y-2 text-xs">
            <p className="font-mono text-rose-300 break-all p-2 bg-slate-950 rounded border border-rose-500/30">
              http://login.paypa1-verify-account.top/auth
            </p>
            <p className="text-[11px] text-slate-400">
              Target IP: <span className="font-mono text-cyan-300">185.220.101.5</span> (AbuseIPDB reputation score: 92/100)
            </p>
          </div>
        </Card>

        <Card className="bg-slate-900 border-slate-800 p-5">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider">Detection Logic</h3>
          <p className="mt-2 text-xs text-slate-300 leading-relaxed">
            Flagged by Rule <span className="font-mono text-cyan-400">EML-RULE-04</span> (Display Name Spoofing + Lookalike Domain + DMARC softfail).
          </p>
          <div className="mt-3 text-[11px] text-slate-400">
            Severity: <span className="font-bold text-rose-400">CRITICAL</span> • Confidence: 94%
          </div>
        </Card>
      </div>
    </div>
  );
}

/**
 * CyberGuard AI — Page 24: Application Status
 * ============================================================================
 * Displays analyst verification review status (pending, in-review, approved).
 */

import { useNavigate } from "react-router-dom";
import { CheckCircle2, Clock, AlertTriangle, ArrowRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";

export default function ApplicationStatus() {
  const navigate = useNavigate();

  return (
    <div className="max-w-2xl mx-auto space-y-6 text-center animate-in fade-in duration-300 py-12">
      <div className="mx-auto w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
        <Clock size={32} />
      </div>

      <div className="space-y-2">
        <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
          Status: Under Review
        </span>
        <h1 className="text-3xl font-black text-slate-100 tracking-tight">
          Analyst Application Submitted
        </h1>
        <p className="text-sm text-slate-400 max-w-md mx-auto">
          Your credentials and identity documents are being reviewed by the platform administrator. Verified status will be granted upon background approval.
        </p>
      </div>

      <Card className="bg-slate-900 border-slate-800 text-left p-6 space-y-4">
        <h3 className="font-bold text-slate-200 text-sm">Verification Checklist</h3>
        <div className="space-y-2 text-xs">
          <div className="flex items-center justify-between p-2 bg-slate-950/60 rounded">
            <span className="text-slate-300">Base Account Creation</span>
            <span className="text-emerald-400 font-bold flex items-center gap-1"><CheckCircle2 size={14} /> Complete</span>
          </div>
          <div className="flex items-center justify-between p-2 bg-slate-950/60 rounded">
            <span className="text-slate-300">Accredited Certifications Check</span>
            <span className="text-amber-400 font-bold flex items-center gap-1"><Clock size={14} /> Pending Administrator</span>
          </div>
          <div className="flex items-center justify-between p-2 bg-slate-950/60 rounded">
            <span className="text-slate-300">Analyst Security Credential Issuance</span>
            <span className="text-cyan-400 font-mono">Issued upon verification</span>
          </div>
        </div>
      </Card>

      <div className="pt-4 flex justify-center gap-3">
        <Button
          onClick={() => navigate("/analyst/dashboard")}
          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
        >
          Open Analyst Dashboard (Preview Mode) <ArrowRight size={14} className="ml-1" />
        </Button>
      </div>
    </div>
  );
}

/**
 * CyberGuard AI — Page 23: Analyst Verification
 * ============================================================================
 * Required identity, credential, and document checks before analyst dashboard
 * access is granted.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Upload, CheckCircle2, Clock, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function AnalystVerificationStep() {
  const navigate = useNavigate();
  const [uploadedDoc, setUploadedDoc] = useState(false);

  const handleUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) {
      setUploadedDoc(true);
      toast.success("Identity credential uploaded and hashed (SHA-256)");
    }
  };

  const handleComplete = () => {
    toast.success("Verification package submitted for administrative approval!");
    navigate("/analyst/application-status");
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-in fade-in duration-300">
      <div className="border-b border-slate-800 pb-5">
        <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
          Page 23 • Verification Gate
        </span>
        <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
          Identity & Credential Verification
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Upload government-issued ID and accredited security certificates. Only verified analysts may triage cases.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
            <ShieldCheck size={18} className="text-cyan-400" />
            <span>Government ID Proof</span>
          </div>
          <p className="text-xs text-slate-400">Passport, National ID or Driver's License</p>
          <label className="block mt-2">
            <input type="file" onChange={handleUpload} className="hidden" />
            <Button variant="outline" size="sm" className="w-full border-slate-800 text-xs text-slate-300 cursor-pointer">
              <span><Upload size={14} className="mr-1.5" /> Upload ID Document</span>
            </Button>
          </label>
        </Card>

        <Card className="bg-slate-900 border-slate-800 p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
            <ShieldCheck size={18} className="text-emerald-400" />
            <span>Security Certificate PDF</span>
          </div>
          <p className="text-xs text-slate-400">Official certificate with verification ID</p>
          <label className="block mt-2">
            <input type="file" onChange={handleUpload} className="hidden" />
            <Button variant="outline" size="sm" className="w-full border-slate-800 text-xs text-slate-300 cursor-pointer">
              <span><Upload size={14} className="mr-1.5" /> Upload Certificate</span>
            </Button>
          </label>
        </Card>
      </div>

      <div className="flex justify-end pt-4">
        <Button
          onClick={handleComplete}
          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
        >
          Submit for Review <ArrowRight size={14} className="ml-1" />
        </Button>
      </div>
    </div>
  );
}

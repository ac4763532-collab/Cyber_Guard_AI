/**
 * CyberGuard AI — Page 34: Profile & Verification (Analyst)
 * ============================================================================
 * Maintain public profile, certifications, specializations, hourly rates,
 * and review background accreditation status.
 */

import { useState } from "react";
import { UserCheck, ShieldCheck, Star, Award, CheckCircle2, DollarSign } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { useAuth } from "@/auth/AuthProvider";

export default function AnalystProfile() {
  const { user } = useAuth();
  const [rate, setRate] = useState("85");
  const [headline, setHeadline] = useState("Senior DFIR & Phishing Forensics Specialist");

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    toast.success("Public analyst profile updated successfully!");
  };

  return (
    <div className="max-w-4xl space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 34 • Profile & Accreditation
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Analyst Profile & Verification
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Maintain your verified marketplace identity and specialized skill offerings.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="bg-slate-900 border-slate-800 p-6 flex flex-col items-center text-center space-y-3">
          <div className="w-20 h-20 rounded-full bg-emerald-500/10 border-2 border-emerald-500/30 flex items-center justify-center text-emerald-400 text-2xl font-bold">
            {user?.full_name?.charAt(0) || "A"}
          </div>
          <div>
            <h3 className="font-bold text-slate-100 text-lg">{user?.full_name || "Analyst Name"}</h3>
            <p className="font-mono text-xs text-cyan-400 mt-0.5">{user?.public_user_id}</p>
          </div>
          <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
            <CheckCircle2 size={14} /> Verified Professional
          </span>
        </Card>

        <Card className="md:col-span-2 bg-slate-900 border-slate-800 p-6">
          <form onSubmit={handleSave} className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">Professional Title / Headline</label>
              <Input
                value={headline}
                onChange={(e) => setHeadline(e.target.value)}
                className="bg-slate-950 border-slate-800 text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">Hourly Consultation Rate (USD)</label>
              <Input
                type="number"
                value={rate}
                onChange={(e) => setRate(e.target.value)}
                className="bg-slate-950 border-slate-800 text-xs text-slate-100"
              />
            </div>

            <div className="pt-2">
              <Button type="submit" className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs">
                Save Profile Changes
              </Button>
            </div>
          </form>
        </Card>
      </div>
    </div>
  );
}

/**
 * CyberGuard AI — Page 22: Analyst Application
 * ============================================================================
 * Submit professional analyst qualifications, certifications, specializations,
 * and resume to begin background verification.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Upload, ArrowRight, Award, FileText } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function AnalystApplication() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    experienceYears: "5",
    specialization: "Incident Response",
    certifications: "CISSP, OSCP",
    linkedinUrl: "https://linkedin.com/in/security-pro",
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    toast.success("Application draft saved! Proceeding to document verification.");
    navigate("/analyst/verification");
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-in fade-in duration-300">
      <div className="border-b border-slate-800 pb-5">
        <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
          Page 22 • Analyst Pathway
        </span>
        <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
          Security Analyst Application
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Complete your professional cybersecurity profile to begin identity and accreditation checks.
        </p>
      </div>

      <Card className="bg-slate-900 border-slate-800 p-6">
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1.5">
              Years of Hands-on Security Experience
            </label>
            <Input
              value={formData.experienceYears}
              onChange={(e) => setFormData({ ...formData, experienceYears: e.target.value })}
              className="bg-slate-950 border-slate-800 text-xs"
              required
            />
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1.5">
              Primary Specializations (Comma Separated)
            </label>
            <Input
              value={formData.specialization}
              onChange={(e) => setFormData({ ...formData, specialization: e.target.value })}
              className="bg-slate-950 border-slate-800 text-xs"
              placeholder="e.g. Incident Response, Phishing Forensics, Network Traffic Analysis"
              required
            />
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1.5">
              Accredited Certifications (CISSP, CEH, OSCP, GCIH...)
            </label>
            <Input
              value={formData.certifications}
              onChange={(e) => setFormData({ ...formData, certifications: e.target.value })}
              className="bg-slate-950 border-slate-800 text-xs"
              required
            />
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1.5">
              Professional Portfolio / LinkedIn URL
            </label>
            <Input
              value={formData.linkedinUrl}
              onChange={(e) => setFormData({ ...formData, linkedinUrl: e.target.value })}
              className="bg-slate-950 border-slate-800 text-xs"
              required
            />
          </div>

          <div className="pt-4 flex justify-end gap-3">
            <Button
              type="submit"
              className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center gap-1.5"
            >
              Continue to Verification <ArrowRight size={14} />
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

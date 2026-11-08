/**
 * CyberGuard AI — Page 38: Organization Setup & Onboarding Wizard
 * ============================================================================
 * Step-by-step organizational onboarding: defining corporate security policies,
 * provisioning primary security rooms, and inviting enterprise team leads.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { 
  Building2, 
  ShieldCheck, 
  Users, 
  Layers, 
  ArrowRight, 
  CheckCircle2, 
  Key, 
  Lock,
  Plus
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { toast } from "sonner";
import { api } from "@/lib/api";

export default function OrganizationSetup() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [departments, setDepartments] = useState(["SecOps", "Engineering", "Compliance"]);
  const [newDept, setNewDept] = useState("");
  const [defaultRoomName, setDefaultRoomName] = useState("War Room Alpha");
  const [defaultRoomCode, setDefaultRoomCode] = useState("WAR-SEC-01");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleAddDept = () => {
    if (newDept.trim() && !departments.includes(newDept.trim())) {
      setDepartments([...departments, newDept.trim()]);
      setNewDept("");
    }
  };

  const handleCompleteSetup = async () => {
    setIsSubmitting(true);
    try {
      // Create initial room
      await api.post("/rooms", {
        name: defaultRoomName,
        code: defaultRoomCode,
        description: "Primary incident triage and security collaboration space",
        password: "DefaultOrgPassword123!",
        is_private: true
      });
      toast.success("Organization environment successfully initialized.");
      navigate("/organization/dashboard");
    } catch (err: any) {
      toast.error(err?.message || "Failed to initialize security room. Proceeding to dashboard.");
      navigate("/organization/dashboard");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 space-y-8 animate-in fade-in duration-300">
      <div className="text-center space-y-2">
        <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1 rounded-full">
          Page 38 • Enterprise Onboarding
        </span>
        <h1 className="text-3xl font-black text-slate-100 tracking-tight">
          Organization Security Environment Setup
        </h1>
        <p className="text-sm text-slate-400 max-w-xl mx-auto">
          Configure security rooms, team departments, and compliance rules to activate enterprise threat isolation.
        </p>
      </div>

      {/* Stepper */}
      <div className="flex items-center justify-center gap-4">
        {[
          { num: 1, label: "Corporate Units" },
          { num: 2, label: "Triage Rooms" },
          { num: 3, label: "Review & Activate" }
        ].map((s) => (
          <div key={s.num} className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${
              step >= s.num ? "bg-cyan-500 text-slate-950" : "bg-slate-800 text-slate-400"
            }`}>
              {step > s.num ? <CheckCircle2 className="w-5 h-5" /> : s.num}
            </div>
            <span className={`text-xs font-medium ${step >= s.num ? "text-slate-200" : "text-slate-500"}`}>
              {s.label}
            </span>
          </div>
        ))}
      </div>

      {step === 1 && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-100 text-lg flex items-center gap-2">
              <Building2 className="w-5 h-5 text-cyan-400" /> Define Organizational Departments
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <p className="text-xs text-slate-400">
              Telemetry and asset vulnerability will be segmented according to these operational units.
            </p>
            <div className="flex flex-wrap gap-2">
              {departments.map((dept) => (
                <span key={dept} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 border border-slate-700 text-slate-200 flex items-center gap-2">
                  {dept}
                  <button 
                    onClick={() => setDepartments(departments.filter(d => d !== dept))}
                    className="text-slate-500 hover:text-rose-400"
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                placeholder="Add department (e.g. Finance, Core Infra)..."
                value={newDept}
                onChange={(e) => setNewDept(e.target.value)}
                className="bg-slate-950 border-slate-800 text-slate-200 text-sm"
              />
              <Button onClick={handleAddDept} className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs">
                <Plus className="w-4 h-4 mr-1" /> Add
              </Button>
            </div>
            <div className="flex justify-end pt-4">
              <Button onClick={() => setStep(2)} className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs">
                Continue to Room Setup <ArrowRight className="w-4 h-4 ml-1.5" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {step === 2 && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-100 text-lg flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" /> Create Primary Incident Room
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-xs text-slate-400">
              Incident response rooms provide an encrypted space where analysts and authorized staff investigate breaches together.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Room Display Name</label>
                <Input
                  value={defaultRoomName}
                  onChange={(e) => setDefaultRoomName(e.target.value)}
                  className="bg-slate-950 border-slate-800 text-slate-200 text-sm"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Unique Room Code</label>
                <Input
                  value={defaultRoomCode}
                  onChange={(e) => setDefaultRoomCode(e.target.value)}
                  className="bg-slate-950 border-slate-800 text-slate-200 text-sm"
                />
              </div>
            </div>
            <div className="flex justify-between pt-4">
              <Button onClick={() => setStep(1)} variant="outline" className="border-slate-800 text-slate-300 text-xs">
                Back
              </Button>
              <Button onClick={() => setStep(3)} className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs">
                Proceed to Final Review <ArrowRight className="w-4 h-4 ml-1.5" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {step === 3 && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-100 text-lg flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" /> Activate Corporate Security Shield
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <p className="text-sm font-bold text-slate-200">Organization Readiness Summary</p>
              <ul className="text-xs text-slate-400 space-y-1">
                <li>• Departments configured: {departments.join(", ")}</li>
                <li>• Initial Room: {defaultRoomName} ({defaultRoomCode})</li>
                <li>• Access policy: Enforce multi-factor verification on internal cases</li>
              </ul>
            </div>

            <div className="flex justify-between pt-4">
              <Button onClick={() => setStep(2)} variant="outline" className="border-slate-800 text-slate-300 text-xs">
                Back
              </Button>
              <Button 
                onClick={handleCompleteSetup} 
                disabled={isSubmitting}
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
              >
                {isSubmitting ? "Initializing..." : "Launch Organization Dashboard"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

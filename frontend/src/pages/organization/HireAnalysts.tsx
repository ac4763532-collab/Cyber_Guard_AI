/**
 * CyberGuard AI — Page 51: Hire & Engage Verified Security Analysts
 * ============================================================================
 * Enterprise procurement of verified cybersecurity analysts: view certifications,
 * hourly or milestone retainers, and assign urgent incident investigation cases.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { 
  UserCheck, 
  Award, 
  Clock, 
  ShieldCheck, 
  Star, 
  DollarSign, 
  ArrowRight,
  Search,
  Filter
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { SimpleModal as Modal } from "@/components/ui/Modal";
import { toast } from "sonner";

export default function HireAnalysts() {
  const navigate = useNavigate();
  const [selectedAnalyst, setSelectedAnalyst] = useState<any | null>(null);
  const [showEngagementModal, setShowEngagementModal] = useState(false);

  const analysts = [
    {
      id: "a1",
      name: "Marcus Vance",
      public_user_id: "marcus-vance-analyst-582914",
      specialization: "Ransomware Containment & Memory Forensics",
      certifications: ["CISSP", "OSCP", "GIAC GREM"],
      experience: "8+ Years",
      rating: 4.9,
      hourly_rate: 150,
      availability: "Immediate",
    },
    {
      id: "a2",
      name: "Elena Rostova",
      public_user_id: "elena-rostova-analyst-194028",
      specialization: "Cloud Threat Hunting (AWS/GCP) & SIEM Triage",
      certifications: ["GCIH", "CCSP", "AWS Security Specialist"],
      experience: "6+ Years",
      rating: 4.8,
      hourly_rate: 135,
      availability: "Available",
    },
    {
      id: "a3",
      name: "David Kim",
      public_user_id: "david-kim-analyst-839210",
      specialization: "Network Intrusion & Zero-Day Exploit Analysis",
      certifications: ["CEH", "OSCE", "CISSP"],
      experience: "10+ Years",
      rating: 5.0,
      hourly_rate: 175,
      availability: "Immediate",
    }
  ];

  const handleEngage = () => {
    toast.success(`Engagement contract created for ${selectedAnalyst?.name}. Direct war room created.`);
    setShowEngagementModal(false);
    navigate("/organization/rooms");
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 51 • Specialized Marketplace
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Hire Verified Security Analysts
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Contract credentialed forensic investigators with platform-verified background checks and escrow milestones.
          </p>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {analysts.map((analyst) => (
          <Card key={analyst.id} className="border-slate-800 bg-slate-900/60 hover:border-cyan-500/40 transition-all flex flex-col justify-between p-5">
            <div className="space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-base font-bold text-slate-100">{analyst.name}</h3>
                  <p className="text-[11px] font-mono text-cyan-400 mt-0.5">{analyst.public_user_id}</p>
                </div>
                <span className="px-2 py-0.5 text-[10px] font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded">
                  {analyst.availability}
                </span>
              </div>

              <div className="text-xs text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-1 font-semibold uppercase text-[10px]">Primary Specialty</span>
                {analyst.specialization}
              </div>

              <div>
                <span className="text-slate-500 block mb-1.5 font-semibold uppercase text-[10px]">Certifications</span>
                <div className="flex flex-wrap gap-1.5">
                  {analyst.certifications.map(cert => (
                    <span key={cert} className="text-[10px] font-bold text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                      {cert}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800">
                <div className="flex items-center gap-1 text-amber-400 font-bold">
                  <Star className="w-3.5 h-3.5 fill-amber-400" />
                  {analyst.rating}
                </div>
                <div className="text-slate-200 font-bold">
                  ${analyst.hourly_rate} <span className="text-slate-500 font-normal">/ hour</span>
                </div>
              </div>
            </div>

            <Button
              onClick={() => {
                setSelectedAnalyst(analyst);
                setShowEngagementModal(true);
              }}
              className="mt-5 w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
            >
              Retain for Investigation <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          </Card>
        ))}
      </div>

      {/* Engagement Modal */}
      <Modal
        isOpen={showEngagementModal}
        onClose={() => setShowEngagementModal(false)}
        title={`Retain ${selectedAnalyst?.name}`}
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Provision an encrypted War Room and authorize a forensic investigation mandate with {selectedAnalyst?.name}.
          </p>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
            <p className="text-slate-200 font-semibold">• Rate: ${selectedAnalyst?.hourly_rate}/hr or Milestone Retainer</p>
            <p className="text-slate-400">• SLA Target: Under 15 minute initial response</p>
            <p className="text-slate-400">• Evidence Vault: Scoped read-only access</p>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setShowEngagementModal(false)} className="text-xs border-slate-800 text-slate-300">
              Cancel
            </Button>
            <Button onClick={handleEngage} className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs">
              Confirm & Create War Room
            </Button>
          </div>
        </div>
      </Modal>

    </div>
  );
}

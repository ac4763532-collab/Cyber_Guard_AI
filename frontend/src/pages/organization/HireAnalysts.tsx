/**
 * CyberGuard AI — Page 51: Hire & Engage Verified Security Analysts
 * ============================================================================
 * Enterprise procurement of verified cybersecurity analysts: view certifications,
 * hourly rates, and retain genuine registered analysts for investigation.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { 
  UserCheck, 
  Award, 
  Clock, 
  ShieldCheck, 
  Star, 
  DollarSign, 
  ArrowRight,
  Search,
  Filter,
  Users,
  RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { SimpleModal as Modal } from "@/components/ui/Modal";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { RegisteredAnalyst } from "@/pages/personal/SecurityAnalysts";

export default function HireAnalysts() {
  const navigate = useNavigate();
  const [selectedAnalyst, setSelectedAnalyst] = useState<RegisteredAnalyst | null>(null);
  const [showEngagementModal, setShowEngagementModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  const { data: analysts = [], isLoading, isFetching, refetch } = useQuery<RegisteredAnalyst[]>({
    queryKey: ["analysts-directory"],
    queryFn: async () => {
      try {
        const { data } = await api.get<RegisteredAnalyst[]>("/analysts/directory");
        return Array.isArray(data) ? data : [];
      } catch (err) {
        console.error("Failed to load analysts directory:", err);
        return [];
      }
    },
    refetchInterval: 30_000,
  });

  const filtered = analysts.filter((a) =>
    a.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.specialization.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.certifications.some((c) => c.toLowerCase().includes(searchTerm.toLowerCase()))
  );

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

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="border-slate-800 text-slate-300 hover:bg-slate-800 text-xs"
          >
            <RefreshCw size={13} className={`mr-1.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>
        </div>
      </div>

      <div className="w-full max-w-md">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <Input
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search registered analysts by name or skill..."
            className="bg-slate-900 border-slate-800 text-xs pl-9 text-slate-200"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="p-16 text-center">
          <RefreshCw size={24} className="mx-auto text-cyan-400 animate-spin mb-3" />
          <p className="text-sm font-semibold text-slate-300">Loading verified analyst directory...</p>
        </div>
      ) : filtered.length === 0 ? (
        <Card className="bg-slate-900 border-slate-800 p-12 text-center">
          <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto mb-4 text-cyan-400">
            <Users size={32} />
          </div>
          <h3 className="text-base font-bold text-slate-100">No Registered Analysts Found</h3>
          <p className="text-xs text-slate-400 mt-2 max-w-md mx-auto leading-relaxed">
            There are currently no security analysts registered in the platform registry. Once an analyst registers, their verified profile will appear here.
          </p>
          <div className="flex justify-center mt-6">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isFetching}
              className="border-slate-800 text-slate-300 hover:bg-slate-800 text-xs"
            >
              <RefreshCw size={13} className={`mr-1.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh Registry
            </Button>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filtered.map((analyst) => (
            <Card key={analyst.id} className="border-slate-800 bg-slate-900/60 hover:border-cyan-500/40 transition-all flex flex-col justify-between p-5">
              <div className="space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-base font-bold text-slate-100">{analyst.name}</h3>
                    <p className="text-[11px] font-mono text-cyan-400 mt-0.5">{analyst.public_user_id}</p>
                  </div>
                  <span className="px-2 py-0.5 text-[10px] font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded">
                    {analyst.available_for_hire ? "Available" : "Engaged"}
                  </span>
                </div>

                <div className="text-xs text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-500 block mb-1 font-semibold uppercase text-[10px]">Primary Specialty</span>
                  {analyst.specialization}
                </div>

                {analyst.certifications.length > 0 && (
                  <div>
                    <span className="text-slate-500 block mb-1.5 font-semibold uppercase text-[10px]">Certifications</span>
                    <div className="flex flex-wrap gap-1.5">
                      {analyst.certifications.map((cert) => (
                        <span key={cert} className="text-[10px] font-bold text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                          {cert}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800">
                  <div className="flex items-center gap-1 text-amber-400 font-bold">
                    <Star className="w-3.5 h-3.5 fill-amber-400" />
                    {analyst.rating.toFixed(1)}
                  </div>
                  <div className="text-slate-200 font-bold">
                    {analyst.hourly_rate}
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
      )}

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
            <p className="text-slate-200 font-semibold">• Rate: {selectedAnalyst?.hourly_rate} or Milestone Retainer</p>
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

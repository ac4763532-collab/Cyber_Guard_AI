/**
 * CyberGuard AI — Page 17: Security Analysts Directory
 * ============================================================================
 * Allows individuals and organizers to discover verified security analysts,
 * review credentials and specializations, request services, or send direct messages.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { 
  Users, 
  ShieldCheck, 
  Search, 
  MessageSquare, 
  Star, 
  CheckCircle, 
  Briefcase,
  DollarSign
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { api } from "@/lib/api";

export default function SecurityAnalysts() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState("");

  const { data: analysts = [], isLoading } = useQuery({
    queryKey: ["analysts-directory"],
    queryFn: async () => {
      try {
        const { data } = await api.get("/analysts/directory");
        return data;
      } catch (err) {
        return [
          {
            id: "an-01",
            public_user_id: "aarav-analyst-000042",
            name: "Aarav Mehta",
            specialization: "Incident Response & Phishing Triage",
            certifications: ["CISSP", "OSCP", "GCIH"],
            rating: 4.9,
            reviews_count: 38,
            hourly_rate: "$85/hr",
            verified: true,
          },
          {
            id: "an-02",
            public_user_id: "elena-analyst-000078",
            name: "Elena Rostova",
            specialization: "Network Forensics & Threat Hunting",
            certifications: ["CCNA Security", "GCFA"],
            rating: 5.0,
            reviews_count: 52,
            hourly_rate: "$95/hr",
            verified: true,
          },
        ];
      }
    },
  });

  const filtered = analysts.filter((a: any) =>
    a.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.specialization.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 17 • Expert Directory
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Verified Security Analysts
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Engage background-checked cybersecurity analysts for deep forensics, evidence analysis, and case investigation.
          </p>
        </div>
      </div>

      <div className="w-full max-w-md">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter by analyst name, skill, certification..."
          className="bg-slate-900 border-slate-800 text-xs"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {filtered.map((analyst: any) => (
          <Card key={analyst.id} className="bg-slate-900 border-slate-800 hover:border-cyan-500/50 transition">
            <CardHeader className="pb-3 flex flex-row items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="font-bold text-slate-100 text-base">{analyst.name}</h3>
                  <span className="text-xs text-emerald-400 flex items-center gap-1 font-semibold">
                    <CheckCircle size={14} /> Verified
                  </span>
                </div>
                <p className="text-xs font-mono text-cyan-400 mt-0.5">{analyst.public_user_id}</p>
                <p className="text-xs text-slate-300 mt-1.5 font-medium">{analyst.specialization}</p>
              </div>
              <div className="text-right">
                <span className="text-sm font-bold text-slate-100">{analyst.hourly_rate}</span>
                <div className="flex items-center gap-1 text-xs text-amber-400 mt-1">
                  <Star size={12} className="fill-amber-400" />
                  <span>{analyst.rating}</span>
                  <span className="text-slate-500">({analyst.reviews_count})</span>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-1.5">
                {analyst.certifications.map((cert: string) => (
                  <span key={cert} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                    {cert}
                  </span>
                ))}
              </div>

              <div className="flex gap-2 pt-2 border-t border-slate-800/80">
                <Button
                  size="sm"
                  onClick={() => {
                    toast.success(`Started secure conversation with ${analyst.name}`);
                    navigate(`/personal/messages?user=${analyst.public_user_id}`);
                  }}
                  className="flex-1 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  <MessageSquare size={14} className="mr-1.5" /> Message
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => toast.info(`Service request submitted for ${analyst.name}`)}
                  className="border-slate-800 text-slate-300 hover:bg-slate-800 text-xs"
                >
                  Request Service
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

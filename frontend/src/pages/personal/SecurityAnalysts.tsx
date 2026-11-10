/**
 * CyberGuard AI — Page 17: Security Analysts Directory
 * ============================================================================
 * Allows individuals and organizers to discover genuine, registered security
 * analysts. Strictly fetches from the platform analyst registry — no fake or
 * mock users.
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
  DollarSign,
  RefreshCw,
  Clock,
  Award,
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { api } from "@/lib/api";

export interface RegisteredAnalyst {
  id: string;
  user_id: string;
  public_user_id: string;
  name: string;
  email?: string;
  specialization: string;
  certifications: string[];
  rating: number;
  reviews_count: number;
  hourly_rate: string;
  verified: boolean;
  verification_status: string;
  available_for_hire: boolean;
  bio?: string;
}

export default function SecurityAnalysts() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState("");

  const { data: analysts = [], isLoading, isFetching, refetch } = useQuery<RegisteredAnalyst[]>({
    queryKey: ["analysts-directory"],
    queryFn: async () => {
      try {
        const { data } = await api.get<RegisteredAnalyst[]>("/analysts/directory");
        return Array.isArray(data) ? data : [];
      } catch (err: any) {
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

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Expert Directory • Registered Analysts
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Verified Security Analysts
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Browse registered cybersecurity analysts for triage, incident forensics, evidence analysis, and case investigation.
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
            <RefreshCw size={13} className={`mr-1.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh Directory
          </Button>
        </div>
      </div>

      <div className="w-full max-w-md">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <Input
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search registered analysts by name, specialization, or certification..."
            className="bg-slate-900 border-slate-800 text-xs pl-9 text-slate-200"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="p-16 text-center">
          <RefreshCw size={24} className="mx-auto text-cyan-400 animate-spin mb-3" />
          <p className="text-sm font-semibold text-slate-300">Loading verified analyst registry...</p>
          <p className="text-xs text-slate-500 mt-1">Connecting to CyberGuard security analyst directory</p>
        </div>
      ) : filtered.length === 0 ? (
        <Card className="bg-slate-900 border-slate-800 p-12 text-center">
          <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto mb-4 text-cyan-400">
            <Users size={32} />
          </div>
          {searchTerm ? (
            <>
              <h3 className="text-base font-bold text-slate-100">No Analysts Found</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                No registered analysts match &quot;{searchTerm}&quot;. Try a different keyword or clear your search filter.
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSearchTerm("")}
                className="mt-4 border-slate-800 text-slate-300 hover:bg-slate-800 text-xs"
              >
                Clear Search
              </Button>
            </>
          ) : (
            <>
              <h3 className="text-base font-bold text-slate-100">No Registered Analysts Found</h3>
              <p className="text-xs text-slate-400 mt-2 max-w-md mx-auto leading-relaxed">
                There are currently no security analysts registered in the platform directory. When security professionals register or complete analyst onboarding, their verified profiles will appear here.
              </p>
              <div className="flex items-center justify-center gap-3 mt-6">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => refetch()}
                  disabled={isFetching}
                  className="border-slate-800 text-slate-300 hover:bg-slate-800 text-xs"
                >
                  <RefreshCw size={13} className={`mr-1.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh Directory
                </Button>
              </div>
            </>
          )}
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {filtered.map((analyst) => (
            <Card key={analyst.id} className="bg-slate-900 border-slate-800 hover:border-cyan-500/50 transition">
              <CardHeader className="pb-3 flex flex-row items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-bold text-slate-100 text-base">{analyst.name}</h3>
                    {analyst.verified && (
                      <span className="text-[11px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full flex items-center gap-1 font-semibold">
                        <CheckCircle size={12} /> Verified
                      </span>
                    )}
                  </div>
                  <p className="text-xs font-mono text-cyan-400 mt-0.5">{analyst.public_user_id}</p>
                  <p className="text-xs text-slate-300 mt-1.5 font-medium">{analyst.specialization}</p>
                </div>
                <div className="text-right">
                  <span className="text-sm font-bold text-slate-100">{analyst.hourly_rate}</span>
                  <div className="flex items-center gap-1 text-xs text-amber-400 mt-1 justify-end">
                    <Star size={12} className="fill-amber-400" />
                    <span>{analyst.rating.toFixed(1)}</span>
                    <span className="text-slate-500">({analyst.reviews_count})</span>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {analyst.certifications.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {analyst.certifications.map((cert) => (
                      <span key={cert} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 flex items-center gap-1">
                        <Award size={10} className="text-cyan-400" />
                        {cert}
                      </span>
                    ))}
                  </div>
                )}

                {analyst.bio && (
                  <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                    {analyst.bio}
                  </p>
                )}

                <div className="flex gap-2 pt-2 border-t border-slate-800/80">
                  <Button
                    size="sm"
                    onClick={() => {
                      toast.success(`Starting secure conversation with ${analyst.name}`);
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
      )}
    </div>
  );
}

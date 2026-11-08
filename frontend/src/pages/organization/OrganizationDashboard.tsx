/**
 * CyberGuard AI — Page 39: Organization Operations Center (Dashboard)
 * ============================================================================
 * Executive view of enterprise security posture: fleet health, active threat
 * rooms, enrolled employees, and contracted security analyst cases.
 * Backed by live backend database aggregation.
 */

import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { 
  Building2, 
  Users, 
  ShieldAlert, 
  Layers, 
  CheckCircle2, 
  UserCheck, 
  ArrowRight,
  Plus,
  AlertTriangle,
  Activity,
  HardDrive
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";

interface RoomSummary {
  id: string;
  code: string;
  name: string;
  description: string | null;
  member_count: number;
}

interface OrgDashboardData {
  active_rooms: number;
  enrolled_devices: number;
  open_alerts: number;
  engaged_analysts: number;
  recent_rooms: RoomSummary[];
}

export default function OrganizationDashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();

  const { data, isLoading } = useQuery<OrgDashboardData>({
    queryKey: ["org-dashboard"],
    queryFn: async () => {
      const res = await api.get<OrgDashboardData>("/dashboard/organization");
      return res.data;
    },
    refetchInterval: 10000,
  });

  const rooms = data?.recent_rooms || [];

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 39 • Enterprise Center
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Organization Security Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Enterprise fleet monitoring, incident room collaboration, and specialized security analyst governance.
          </p>
        </div>

        <div className="flex gap-3">
          <Button
            onClick={() => navigate("/organization/rooms")}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
          >
            <Plus className="w-4 h-4 mr-1.5" /> Manage Rooms
          </Button>
          <Button
            onClick={() => navigate("/organization/analysts")}
            variant="outline"
            className="border-slate-800 hover:bg-slate-900 text-slate-200 text-xs font-medium"
          >
            Hire Analysts
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Active Security Rooms</span>
            <Layers className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-slate-100">
              {isLoading ? "..." : (data?.active_rooms ?? 0)}
            </span>
            <span className="text-xs text-slate-400">War rooms</span>
          </div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Enrolled Fleet Devices</span>
            <HardDrive className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-slate-100">
              {isLoading ? "..." : (data?.enrolled_devices ?? 0)}
            </span>
            <span className="text-xs text-slate-400">Active endpoints</span>
          </div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Open Incidents & Alerts</span>
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-slate-100">
              {isLoading ? "..." : (data?.open_alerts ?? 0)}
            </span>
            <span className="text-xs text-rose-400 font-semibold">Triage required</span>
          </div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Verified Analysts Engaged</span>
            <UserCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-slate-100">
              {isLoading ? "..." : (data?.engaged_analysts ?? 0)}
            </span>
            <span className="text-xs text-emerald-400 font-semibold">Contracted experts</span>
          </div>
        </Card>
      </div>

      {/* Grid: Rooms & Quick Navigation */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-slate-200">Corporate Security Rooms</h2>
            <Button
              variant="outline"
              onClick={() => navigate("/organization/rooms")}
              className="text-xs border-slate-800 text-slate-300"
            >
              View All
            </Button>
          </div>

          {isLoading ? (
            <div className="p-8 text-center"><Spinner label="Loading rooms..." /></div>
          ) : rooms.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900/40 border border-slate-800 text-center">
              <Layers className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <p className="text-sm font-semibold text-slate-300">No rooms active yet</p>
              <p className="text-xs text-slate-500 mt-1">Create an incident room to collaborate with your team and contracted analysts.</p>
              <Button
                onClick={() => navigate("/organization/rooms")}
                className="mt-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
              >
                Create Room
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {rooms.map((room) => (
                <div
                  key={room.id}
                  onClick={() => navigate(`/organization/rooms/${room.id}`)}
                  className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-all space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded">
                      {room.code}
                    </span>
                    <span className="text-xs text-slate-400">
                      {room.member_count} members
                    </span>
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-100">{room.name}</h3>
                    <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">{room.description || "Active collaboration workspace."}</p>
                  </div>
                  <div className="text-xs text-cyan-400 flex items-center font-semibold pt-1">
                    Enter Workspace <ArrowRight className="w-3.5 h-3.5 ml-1" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Quick Actions Panel */}
        <div className="space-y-4">
          <h2 className="text-base font-bold text-slate-200">Enterprise Administration</h2>
          <Card className="border-slate-800 bg-slate-900/60 divide-y divide-slate-800">
            <div 
              onClick={() => navigate("/organization/employees")}
              className="p-4 hover:bg-slate-800/40 cursor-pointer transition-all flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <Users className="w-5 h-5 text-indigo-400" />
                <div>
                  <p className="text-xs font-bold text-slate-200">Employee Directory</p>
                  <p className="text-[11px] text-slate-400">Enroll corporate users and sync endpoint policies</p>
                </div>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500" />
            </div>

            <div 
              onClick={() => navigate("/organization/analysts")}
              className="p-4 hover:bg-slate-800/40 cursor-pointer transition-all flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <UserCheck className="w-5 h-5 text-emerald-400" />
                <div>
                  <p className="text-xs font-bold text-slate-200">Hire Verified Analysts</p>
                  <p className="text-[11px] text-slate-400">Escalate severe incidents to credentialed experts</p>
                </div>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500" />
            </div>

            <div 
              onClick={() => navigate("/organization/settings")}
              className="p-4 hover:bg-slate-800/40 cursor-pointer transition-all flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <Building2 className="w-5 h-5 text-cyan-400" />
                <div>
                  <p className="text-xs font-bold text-slate-200">Organization Settings</p>
                  <p className="text-[11px] text-slate-400">Manage tenant keys, billing, and audit logs</p>
                </div>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500" />
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

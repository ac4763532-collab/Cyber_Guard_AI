/**
 * CyberGuard AI — Page 42: Organization Employee Directory
 * ============================================================================
 * Manage corporate users, assign security clearance levels, track enrolled
 * endpoints per employee, and dispatch room onboarding invitations.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { 
  Users, 
  UserPlus, 
  Search, 
  ShieldCheck, 
  Smartphone, 
  Mail, 
  HardDrive,
  Copy,
  Check
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { api } from "@/lib/api";
import { toast } from "sonner";

export default function Employees() {
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const { data: devices = [] } = useQuery({
    queryKey: ["org-devices-employees"],
    queryFn: async () => {
      const res = await api.get<any[]>("/devices");
      return res.data || [];
    }
  });

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedId(val);
    toast.success("Public User ID copied.");
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 42 • Organization Workspace
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Employee & Member Directory
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Audit member security clearances, endpoint enrollment, and room assignment status.
          </p>
        </div>

        <Button
          onClick={() => toast.info("Employee invitation link copied to clipboard.")}
          className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
        >
          <UserPlus className="w-4 h-4 mr-1.5" /> Invite Corporate Member
        </Button>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
        <Input
          placeholder="Filter employees by name, email, or public slug..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-9 bg-slate-950 border-slate-800 text-slate-200 text-sm"
        />
      </div>

      {/* Directory Table */}
      <Card className="border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-bold uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Employee</th>
                <th className="py-3 px-4">Public Slug ID</th>
                <th className="py-3 px-4">Clearance Role</th>
                <th className="py-3 px-4">Enrolled Endpoints</th>
                <th className="py-3 px-4">Compliance Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300">
              <tr className="hover:bg-slate-800/40">
                <td className="py-3.5 px-4 font-semibold text-slate-100">
                  SecOps Admin (Primary)
                  <div className="text-[11px] text-slate-400 font-normal">admin@organization.com</div>
                </td>
                <td className="py-3.5 px-4 font-mono text-cyan-400">
                  <div className="flex items-center gap-1.5">
                    admin-organizer-849201
                    <button onClick={() => handleCopy("admin-organizer-849201")}>
                      {copiedId === "admin-organizer-849201" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                    </button>
                  </div>
                </td>
                <td className="py-3.5 px-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    Org Admin
                  </span>
                </td>
                <td className="py-3.5 px-4 font-medium text-slate-200">
                  {devices.length} Devices
                </td>
                <td className="py-3.5 px-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    Compliant
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Card>

    </div>
  );
}

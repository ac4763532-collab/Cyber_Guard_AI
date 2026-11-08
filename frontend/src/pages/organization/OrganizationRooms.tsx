/**
 * CyberGuard AI — Page 40: Organization Security Rooms Hub
 * ============================================================================
 * Room management for organizations: list rooms, create new war rooms,
 * manage security passwords, and invite internal or external participants.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { 
  Layers, 
  Plus, 
  Key, 
  Lock, 
  Users, 
  ArrowRight, 
  Search, 
  Copy, 
  Check, 
  ShieldAlert,
  Send
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { SimpleModal as Modal } from "@/components/ui/Modal";
import { api } from "@/lib/api";
import { toast } from "sonner";

export default function OrganizationRooms() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [selectedRoomId, setSelectedRoomId] = useState<string | null>(null);

  // Create Room State
  const [newRoomName, setNewRoomName] = useState("");
  const [newRoomCode, setNewRoomCode] = useState("");
  const [newRoomDesc, setNewRoomDesc] = useState("");
  const [newRoomPassword, setNewRoomPassword] = useState("");

  // Invite State
  const [invitePublicUserId, setInvitePublicUserId] = useState("");

  const { data: rooms = [], isLoading } = useQuery({
    queryKey: ["org-rooms-all"],
    queryFn: async () => {
      const res = await api.get<any[]>("/rooms/me");
      return res.data || [];
    }
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      return await api.post("/rooms", {
        name: newRoomName,
        code: newRoomCode,
        description: newRoomDesc,
        password: newRoomPassword || undefined,
        is_private: true
      });
    },
    onSuccess: () => {
      toast.success("Security room created successfully.");
      setShowCreateModal(false);
      setNewRoomName("");
      setNewRoomCode("");
      setNewRoomDesc("");
      setNewRoomPassword("");
      queryClient.invalidateQueries({ queryKey: ["org-rooms-all"] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to create security room.");
    }
  });

  const inviteMutation = useMutation({
    mutationFn: async () => {
      if (!selectedRoomId) return;
      return await api.post(`/rooms/${selectedRoomId}/invitations`, {
        invited_public_user_id: invitePublicUserId
      });
    },
    onSuccess: () => {
      toast.success("Invitation dispatched successfully.");
      setShowInviteModal(false);
      setInvitePublicUserId("");
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to send room invitation.");
    }
  });

  const filteredRooms = rooms.filter(r => 
    (r as any).name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (r as any).code?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 40 • Organization Workspace
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Incident War Rooms
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Segment sensitive breach responses into isolated spaces with private credentials and direct invitations.
          </p>
        </div>

        <Button
          onClick={() => setShowCreateModal(true)}
          className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
        >
          <Plus className="w-4 h-4 mr-1.5" /> Create New Room
        </Button>
      </div>

      {/* Filter Bar */}
      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
          <Input
            placeholder="Search by room name or code..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-slate-950 border-slate-800 text-slate-200 text-sm"
          />
        </div>
      </div>

      {/* Rooms List */}
      {filteredRooms.length === 0 ? (
        <Card className="border-slate-800 bg-slate-900/40 p-12 text-center">
          <Layers className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-bold text-slate-200">No rooms found</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            Create an incident room to begin collaborating on breach response workflows.
          </p>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredRooms.map((room: any) => (
            <Card key={room.id} className="border-slate-800 bg-slate-900/60 hover:border-cyan-500/40 transition-all flex flex-col justify-between">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">
                    {room.code}
                  </span>
                  <div className="flex items-center gap-1.5 text-xs text-slate-400">
                    <Users className="w-3.5 h-3.5" />
                    {room.members?.length || 1}
                  </div>
                </div>
                <CardTitle className="text-slate-100 text-base mt-2">{room.name}</CardTitle>
                <p className="text-xs text-slate-400 line-clamp-2 mt-1">{room.description || "Active incident workspace."}</p>
              </CardHeader>
              <CardContent className="pt-0 border-t border-slate-800/80 flex items-center justify-between mt-4 py-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSelectedRoomId(room.id);
                    setShowInviteModal(true);
                  }}
                  className="border-slate-800 text-xs text-slate-300 hover:bg-slate-800"
                >
                  <Send className="w-3.5 h-3.5 mr-1" /> Invite
                </Button>
                <Button
                  size="sm"
                  onClick={() => navigate(`/organization/rooms/${room.id}`)}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  Enter Room <ArrowRight className="w-3.5 h-3.5 ml-1" />
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create Incident War Room"
      >
        <div className="space-y-4">
          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">Room Name</label>
            <Input
              placeholder="e.g. Ransomware Containment Alpha"
              value={newRoomName}
              onChange={(e) => setNewRoomName(e.target.value)}
              className="bg-slate-950 border-slate-800 text-slate-200 text-sm"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">Room Code (unique)</label>
            <Input
              placeholder="e.g. SEC-WAR-402"
              value={newRoomCode}
              onChange={(e) => setNewRoomCode(e.target.value)}
              className="bg-slate-950 border-slate-800 text-slate-200 text-sm"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">Optional Entry Password</label>
            <Input
              type="password"
              placeholder="Leave blank for open internal join"
              value={newRoomPassword}
              onChange={(e) => setNewRoomPassword(e.target.value)}
              className="bg-slate-950 border-slate-800 text-slate-200 text-sm"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">Scope & Description</label>
            <textarea
              placeholder="Details on the scope and members..."
              value={newRoomDesc}
              onChange={(e) => setNewRoomDesc(e.target.value)}
              rows={3}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setShowCreateModal(false)} className="text-xs border-slate-800 text-slate-300">
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={createMutation.isPending || !newRoomName || !newRoomCode}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
            >
              {createMutation.isPending ? "Creating..." : "Create Room"}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Invite Modal */}
      <Modal
        isOpen={showInviteModal}
        onClose={() => setShowInviteModal(false)}
        title="Invite Member by Public User ID"
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Enter the exact public user ID of the individual or analyst (e.g. <span className="font-mono text-cyan-400">john-doe-analyst-482910</span>).
          </p>
          <Input
            placeholder="e.g. alex-analyst-123456"
            value={invitePublicUserId}
            onChange={(e) => setInvitePublicUserId(e.target.value)}
            className="bg-slate-950 border-slate-800 text-slate-200 text-sm font-mono"
          />
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setShowInviteModal(false)} className="text-xs border-slate-800 text-slate-300">
              Cancel
            </Button>
            <Button
              onClick={() => inviteMutation.mutate()}
              disabled={inviteMutation.isPending || !invitePublicUserId}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
            >
              {inviteMutation.isPending ? "Sending..." : "Dispatch Invitation"}
            </Button>
          </div>
        </div>
      </Modal>

    </div>
  );
}

/**
 * CyberGuard AI — Page 57: My Rooms & Invitations
 * ============================================================================
 * Allows individual users to:
 * 1. Directly join a private room by entering Room ID / Code + Password.
 * 2. View and manage all rooms they are an active member of.
 * 3. Review and accept/decline incoming invitations sent by Organizers.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { 
  DoorOpen, 
  Key, 
  ShieldCheck, 
  Users, 
  Check, 
  X, 
  ArrowRight, 
  Lock, 
  Building2,
  Calendar,
  Sparkles
} from "lucide-react";
import { toast } from "sonner";
import { useNavigate } from "react-router-dom";

import { api } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import type { Room, RoomInvitation, JoinRoomResponse } from "@/types";

export default function MyRoomsAndInvitations() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [isJoinModalOpen, setIsJoinModalOpen] = useState(false);
  const [roomCode, setRoomCode] = useState("");
  const [roomPassword, setRoomPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  // ── 1. Fetch joined rooms ─────────────────────────────────────────────
  const { data: rooms = [], isLoading: isLoadingRooms } = useQuery<Room[]>({
    queryKey: ["my-rooms"],
    queryFn: async () => {
      try {
        const { data } = await api.get<Room[]>("/rooms/me");
        return data;
      } catch (err) {
        return [];
      }
    },
  });

  // ── 2. Fetch pending invitations ──────────────────────────────────────
  const { data: invitations = [], isLoading: isLoadingInvites } = useQuery<RoomInvitation[]>({
    queryKey: ["my-room-invitations"],
    queryFn: async () => {
      try {
        const { data } = await api.get<RoomInvitation[]>("/rooms/invitations/me");
        return data;
      } catch (err) {
        return [];
      }
    },
  });

  // ── 3. Direct Join Mutation ───────────────────────────────────────────
  const handleDirectJoin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roomCode.trim()) {
      toast.error("Please enter a valid Room ID or Code");
      return;
    }

    setIsSubmitting(true);
    try {
      const { data } = await api.post<JoinRoomResponse>("/rooms/join", {
        room_code: roomCode.trim(),
        password: roomPassword.trim() || undefined,
      });

      toast.success(data.message || "Successfully joined room!");
      setIsJoinModalOpen(false);
      setRoomCode("");
      setRoomPassword("");
      queryClient.invalidateQueries({ queryKey: ["my-rooms"] });
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || err.message || "Failed to join room");
    } finally {
      setIsSubmitting(false);
    }
  };

  // ── 4. Respond to Invitation Mutation ─────────────────────────────────
  const respondInviteMutation = useMutation({
    mutationFn: async ({ id, accept }: { id: string; accept: boolean }) => {
      const action = accept ? "accept" : "decline";
      await api.post(`/room-invitations/${id}/${action}`);
    },
    onSuccess: (_, { accept }) => {
      toast.success(accept ? "Invitation accepted! Room added." : "Invitation declined.");
      queryClient.invalidateQueries({ queryKey: ["my-room-invitations"] });
      queryClient.invalidateQueries({ queryKey: ["my-rooms"] });
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error?.message || "Failed to process invitation");
    },
  });

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* ── Page Header ───────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
              Page 57 • Room Workspace
            </span>
          </div>
          <h1 className="text-3xl font-black tracking-tight text-slate-100 mt-2">
            My Rooms & Invitations
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Directly join private company security rooms with your Room ID & Password, or accept organizer invitations.
          </p>
        </div>

        <Button
          onClick={() => setIsJoinModalOpen(true)}
          className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold flex items-center gap-2 shadow-[0_0_20px_rgba(6,182,212,0.3)] transition"
        >
          <DoorOpen size={18} />
          Direct Join Room
        </Button>
      </div>

      {/* ── Direct Join Room Modal ────────────────────────────────────── */}
      {isJoinModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-md p-4">
          <div className="w-full max-w-md bg-slate-900 border border-cyan-500/40 rounded-2xl p-6 shadow-[0_0_35px_rgba(6,182,212,0.2)] animate-in zoom-in-95">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                  <Key size={20} />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 text-base">Direct Room Join</h3>
                  <p className="text-xs text-slate-400">Enter room credentials provided by organizer</p>
                </div>
              </div>
              <button
                onClick={() => setIsJoinModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded-lg"
              >
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleDirectJoin} className="space-y-4 mt-5">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                  Room ID or Reference Code <span className="text-rose-400">*</span>
                </label>
                <Input
                  value={roomCode}
                  onChange={(e) => setRoomCode(e.target.value)}
                  placeholder="e.g. ROOM-7X9B or Room UUID"
                  required
                  className="bg-slate-950 border-slate-800 text-slate-100 font-mono text-sm focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                  Room Password <span className="text-slate-500">(if password-protected)</span>
                </label>
                <Input
                  type="password"
                  value={roomPassword}
                  onChange={(e) => setRoomPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="bg-slate-950 border-slate-800 text-slate-100 text-sm focus:border-cyan-500"
                />
              </div>

              <div className="pt-2 flex gap-3 justify-end">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => setIsJoinModalOpen(false)}
                  className="text-slate-400 hover:bg-slate-800 text-xs"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  {isSubmitting ? "Verifying..." : "Join Room Now"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Pending Invitations Section ───────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Sparkles size={18} className="text-cyan-400" />
            Pending Invitations
            {invitations.length > 0 && (
              <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {invitations.length}
              </span>
            )}
          </h2>
          <span className="text-xs text-slate-500">Sent to your public ID: {user?.public_user_id}</span>
        </div>

        {isLoadingInvites ? (
          <div className="p-8 text-center text-slate-500 text-sm">Loading invitations...</div>
        ) : invitations.length === 0 ? (
          <Card className="bg-slate-900/40 border-slate-800/80">
            <CardContent className="p-6 text-center text-slate-500 text-sm">
              No pending room invitations. Organizers can invite you using your public user ID:{" "}
              <span className="font-mono text-cyan-400 font-bold">{user?.public_user_id}</span>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {invitations.map((inv) => (
              <Card key={inv.id} className="bg-slate-900 border-slate-800 hover:border-cyan-500/40 transition">
                <CardContent className="p-5 flex items-center justify-between">
                  <div className="space-y-1">
                    <p className="font-bold text-slate-200">{inv.room_name}</p>
                    <p className="text-xs text-slate-400">
                      Invited by <span className="text-slate-300">{inv.inviter_name}</span> as <span className="text-cyan-400 uppercase font-semibold">{inv.role}</span>
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono">Code: {inv.public_room_id}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      onClick={() => respondInviteMutation.mutate({ id: inv.id, accept: true })}
                      disabled={respondInviteMutation.isPending}
                      className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
                    >
                      <Check size={14} className="mr-1" /> Accept
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => respondInviteMutation.mutate({ id: inv.id, accept: false })}
                      disabled={respondInviteMutation.isPending}
                      className="text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 text-xs"
                    >
                      <X size={14} />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* ── My Joined Rooms Section ───────────────────────────────────── */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
          <Building2 size={18} className="text-cyan-400" />
          Active Room Memberships
          <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
            {rooms.length}
          </span>
        </h2>

        {isLoadingRooms ? (
          <div className="p-8 text-center text-slate-500 text-sm">Loading joined rooms...</div>
        ) : rooms.length === 0 ? (
          <Card className="bg-slate-900/40 border-slate-800 text-center p-12">
            <CardContent className="space-y-3">
              <div className="mx-auto w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <DoorOpen size={24} />
              </div>
              <h3 className="font-bold text-slate-200">No rooms joined yet</h3>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Join a room using the Direct Join button above or accept an invitation from your organization.
              </p>
              <Button
                onClick={() => setIsJoinModalOpen(true)}
                variant="outline"
                size="sm"
                className="border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 mt-2 text-xs"
              >
                Enter Room Code
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {rooms.map((room) => (
              <Card key={room.id} className="bg-slate-900 border-slate-800 hover:border-cyan-500/50 transition-all group flex flex-col justify-between">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-400 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                      {room.public_room_id}
                    </span>
                    <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span> Active
                    </span>
                  </div>
                  <CardTitle className="text-base font-bold text-slate-100 mt-2 group-hover:text-cyan-300 transition">
                    {room.name}
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400 line-clamp-2">
                    {room.description || "Private security collaboration room."}
                  </CardDescription>
                </CardHeader>

                <CardContent className="pt-0 space-y-4">
                  <div className="flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80 pt-3">
                    <div className="flex items-center gap-1.5">
                      <Users size={14} className="text-slate-500" />
                      <span>{room.member_count || 1} Members</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Lock size={14} className="text-slate-500" />
                      <span>{room.join_policy}</span>
                    </div>
                  </div>

                  <Button
                    onClick={() => navigate(`/organization/rooms/${room.id}`)}
                    className="w-full bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-slate-200 font-semibold text-xs transition flex items-center justify-center gap-1.5"
                  >
                    Open Workspace <ArrowRight size={14} />
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}

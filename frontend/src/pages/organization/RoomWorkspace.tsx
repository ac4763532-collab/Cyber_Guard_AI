/**
 * CyberGuard AI — Page 41: Organization Room Workspace
 * ============================================================================
 * Scoped room communication, forensic evidence sharing, live task coordination,
 * and roster of active participants in this security room.
 */

import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { 
  Layers, 
  Send, 
  Users, 
  ShieldCheck, 
  FileText, 
  ArrowLeft, 
  Lock,
  Clock,
  HardDrive
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { api } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";
import { toast } from "sonner";

export default function RoomWorkspace() {
  const { roomId } = useParams<{ roomId: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const [messageText, setMessageText] = useState("");

  const { data: rooms = [] } = useQuery({
    queryKey: ["org-rooms-all"],
    queryFn: async () => {
      const res = await api.get<any[]>("/rooms/me");
      return res.data || [];
    }
  });

  const room = (rooms as any[]).find((r: any) => r.id === roomId || r.code === roomId);

  const { data: messages = [], isLoading } = useQuery({
    queryKey: ["room-messages", roomId],
    queryFn: async () => {
      // Scoped room messages
      try {
        const res = await api.get<any[]>(`/messages?scope=room&room_id=${roomId}`);
        return res.data || [];
      } catch {
        return [];
      }
    },
    refetchInterval: 4000
  });

  const sendMessageMutation = useMutation({
    mutationFn: async () => {
      return await api.post("/messages", {
        room_id: roomId,
        scope: "room",
        body: messageText
      });
    },
    onSuccess: () => {
      setMessageText("");
      queryClient.invalidateQueries({ queryKey: ["room-messages", roomId] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to send room message.");
    }
  });

  return (
    <div className="h-[calc(100vh-8rem)] flex flex-col space-y-4 animate-in fade-in duration-300">
      
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("/organization/rooms")}
            className="border-slate-800 text-slate-300 text-xs"
          >
            <ArrowLeft className="w-4 h-4 mr-1" /> All Rooms
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded">
                {room?.code || "SEC-WAR"}
              </span>
              <h1 className="text-lg font-bold text-slate-100">{room?.name || "Incident Workspace"}</h1>
            </div>
            <p className="text-xs text-slate-400">{room?.description || "Encrypted room communication channel"}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-emerald-400 flex items-center gap-1.5 font-semibold bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 rounded-full">
            <ShieldCheck className="w-3.5 h-3.5" /> Room Scope Isolation
          </span>
        </div>
      </div>

      {/* Main Split Layout */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-4 gap-4 overflow-hidden">
        
        {/* Chat Stream (3 cols) */}
        <div className="lg:col-span-3 flex flex-col rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
          <div className="flex-1 p-4 overflow-y-auto space-y-3">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500">
                <Layers className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-xs">No messages in this war room yet. Start the briefing below.</p>
              </div>
            ) : (
              messages.map((m: any) => {
                const isMe = m.sender_id === user?.id;
                return (
                  <div key={m.id} className={`flex flex-col ${isMe ? "items-end" : "items-start"}`}>
                    <div className="flex items-center gap-1.5 text-[10px] text-slate-400 mb-1">
                      <span className="font-bold text-slate-300">{m.sender_name || "Agent"}</span>
                      <span>•</span>
                      <span>{new Date(m.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                    </div>
                    <div className={`p-3 rounded-xl text-xs max-w-lg ${
                      isMe 
                        ? "bg-cyan-500 text-slate-950 font-medium rounded-tr-none" 
                        : "bg-slate-800 text-slate-200 border border-slate-700 rounded-tl-none"
                    }`}>
                      {m.body}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <div className="p-3 border-t border-slate-800 bg-slate-950 flex gap-2">
            <Input
              placeholder="Post message to room participants..."
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  if (messageText.trim()) sendMessageMutation.mutate();
                }
              }}
              className="bg-slate-900 border-slate-800 text-slate-200 text-xs"
            />
            <Button
              onClick={() => sendMessageMutation.mutate()}
              disabled={sendMessageMutation.isPending || !messageText.trim()}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
            >
              <Send className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Sidebar Roster & Artifacts (1 col) */}
        <div className="space-y-4 overflow-y-auto">
          <Card className="border-slate-800 bg-slate-900/60 p-4 space-y-3">
            <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <Users className="w-4 h-4 text-cyan-400" /> Active Roster ({room?.members?.length || 1})
            </h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs p-2 rounded-lg bg-slate-950 border border-slate-800">
                <div>
                  <p className="font-semibold text-slate-200">{user?.email}</p>
                  <p className="text-[10px] text-cyan-400">Admin Owner</p>
                </div>
              </div>
            </div>
          </Card>

          <Card className="border-slate-800 bg-slate-900/60 p-4 space-y-3">
            <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-400" /> Attached Evidence
            </h3>
            <p className="text-[11px] text-slate-400">
              Evidence artifacts tagged with room code <span className="font-mono text-cyan-400">{room?.code}</span> appear here automatically.
            </p>
          </Card>
        </div>

      </div>

    </div>
  );
}

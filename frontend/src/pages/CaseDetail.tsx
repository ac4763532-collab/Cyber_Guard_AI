/**
 * CyberGuard AI — Case Detail Page
 * ============================================================================
 * 
 * The collaborative workspace for a single case.
 * 
 * Layout:
 *   - Left Pane: Conversation (Client <-> Analyst).
 *   - Right Pane: Investigation Details, SLA, and Evidence.
 * 
 * Features:
 *   - Polls for new messages every 5 seconds (MVP real-time).
 *   - Send message mutation with optimistic UI updates.
 *   - Evidence upload (mocked file input for UI demonstration).
 */

import { useState, useRef, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, Send, Paperclip, Clock, FileText
} from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { SecurityCase } from "@/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { formatDate, formatRelativeTime } from "@/lib/utils";


// ============================================================================
// LOCAL TYPES (Messages & Conversations)
// ============================================================================

interface CaseMessage {
  id: string;
  conversation_id: string;
  sender_id: string;
  sender_name: string;
  body: string;
  created_at: string;
  is_me: boolean; // Computed by backend or frontend
}


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const [newMessage, setNewMessage] = useState("");

  // ── Fetch Case Details ────────────────────────────────────────────────
  const { data: caseData, isLoading: isLoadingCase } = useQuery({
    queryKey: ["case", id],
    queryFn: async () => {
      const { data } = await api.get<SecurityCase>(`/cases/${id}`);
      return data;
    },
    enabled: !!id,
  });

  // ── Fetch Messages (Polling every 5s) ─────────────────────────────────
  const { data: messages, isLoading: isLoadingMessages } = useQuery({
    queryKey: ["case", id, "messages"],
    queryFn: async () => {
      // In the actual backend, this might be /cases/{id}/conversations/{conv_id}/messages
      // We are assuming a convenience endpoint /cases/{id}/messages for the client view.
      const { data } = await api.get<CaseMessage[]>(`/cases/${id}/messages`);
      return data;
    },
    enabled: !!id,
    refetchInterval: 5000,
  });

  // ── Scroll to bottom when messages change ─────────────────────────────
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  // ── Send Message Mutation ─────────────────────────────────────────────
  const sendMutation = useMutation({
    mutationFn: async (body: string) => {
      const { data } = await api.post(`/cases/${id}/messages`, { body });
      return data;
    },
    onSuccess: () => {
      setNewMessage("");
      queryClient.invalidateQueries({ queryKey: ["case", id, "messages"] });
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to send message");
    },
  });

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMessage.trim()) return;
    sendMutation.mutate(newMessage);
  };

  // ── Render States ─────────────────────────────────────────────────────
  if (isLoadingCase || !caseData) {
    return <div className="p-12"><Spinner size="lg" label="Loading case..." /></div>;
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col space-y-4">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-start gap-4 shrink-0">
        <Button 
          variant="ghost" 
          size="sm" 
          onClick={() => navigate("/cases")}
          className="mt-1 -ml-2 text-slate-500"
        >
          <ArrowLeft size={16} />
        </Button>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              {caseData.title}
            </h1>
            <Badge status={caseData.status} withDot />
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Case #{caseData.case_number} • Opened {formatDate(caseData.opened_at)}
          </p>
        </div>
      </div>

      {/* ── Main Split Pane ────────────────────────────────────────────── */}
      <div className="flex flex-1 gap-6 overflow-hidden">
        
        {/* Left Pane: Conversation */}
        <Card className="flex flex-1 flex-col overflow-hidden">
          <CardHeader className="border-b border-slate-200 dark:border-slate-800 py-3 shrink-0">
            <CardTitle className="text-sm font-medium">Conversation</CardTitle>
          </CardHeader>
          
          {/* Message List */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {isLoadingMessages ? (
              <Spinner label="Loading messages..." />
            ) : messages?.length === 0 ? (
              <div className="text-center text-sm text-slate-500 py-8">
                No messages yet. Send a message to start the conversation.
              </div>
            ) : (
              messages?.map((msg) => (
                <div 
                  key={msg.id} 
                  className={`flex flex-col max-w-[80%] ${msg.is_me ? "ml-auto items-end" : "mr-auto items-start"}`}
                >
                  <span className="text-xs text-slate-400 mb-1 px-1">
                    {msg.sender_name} • {formatRelativeTime(msg.created_at)}
                  </span>
                  <div className={`rounded-xl px-4 py-2 text-sm ${
                    msg.is_me 
                      ? "bg-brand-600 text-white rounded-tr-sm" 
                      : "bg-slate-100 text-slate-900 rounded-tl-sm dark:bg-slate-800 dark:text-slate-100"
                  }`}>
                    {msg.body}
                  </div>
                </div>
              ))
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="p-3 border-t border-slate-200 dark:border-slate-800 shrink-0">
            <form onSubmit={handleSend} className="flex gap-2">
              <Button type="button" variant="ghost" size="sm" className="shrink-0 text-slate-400">
                <Paperclip size={20} />
              </Button>
              <input
                type="text"
                placeholder="Type a message..."
                className="flex-1 rounded-lg border border-slate-300 bg-white px-3 text-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                disabled={sendMutation.isPending}
              />
              <Button type="submit" size="sm" disabled={!newMessage.trim() || sendMutation.isPending} isLoading={sendMutation.isPending}>
                <Send size={16} className="mr-1" /> Send
              </Button>
            </form>
          </div>
        </Card>

        {/* Right Pane: Details & Evidence */}
        <div className="w-80 flex flex-col gap-4 shrink-0 hidden lg:flex overflow-y-auto">
          
          {/* Details Card */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Case Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              <div>
                <p className="text-slate-500">Priority</p>
                <p className="font-medium uppercase">{caseData.priority}</p>
              </div>
              <div>
                <p className="text-slate-500">Assigned To</p>
                <p className="font-medium">{caseData.assigned_to_id ? "Analyst Assigned" : "Unassigned"}</p>
              </div>
              <div>
                <p className="text-slate-500 flex items-center gap-1">
                  <Clock size={14} /> SLA Deadline
                </p>
                <p className="font-medium text-red-600 dark:text-red-400">
                  {caseData.sla_deadline_at ? formatDate(caseData.sla_deadline_at) : "None"}
                </p>
              </div>
              <div>
                <p className="text-slate-500">Category</p>
                <p className="font-medium uppercase">{caseData.category.replace("_", " ")}</p>
              </div>
            </CardContent>
          </Card>

          {/* Evidence Card */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <FileText size={16} /> Evidence
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button variant="outline" size="sm" className="w-full border-dashed">
                + Upload File
              </Button>
              {/* Mock evidence list */}
              <div className="flex items-center justify-between text-sm p-2 rounded-md bg-slate-50 dark:bg-slate-800/50">
                <div className="flex items-center gap-2 truncate">
                  <FileText size={14} className="text-slate-400" />
                  <span className="truncate">auth.log</span>
                </div>
                <span className="text-xs text-slate-400 shrink-0">1.2 MB</span>
              </div>
            </CardContent>
          </Card>

        </div>
      </div>
    </div>
  );
}
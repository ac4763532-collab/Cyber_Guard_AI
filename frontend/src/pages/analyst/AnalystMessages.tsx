/**
 * CyberGuard AI — Page 31: Analyst Secure Messages
 * ============================================================================
 * Case communications and direct conversations between verified analysts
 * and authorized case participants/clients backed by persistent database storage.
 * Messages are strictly isolated per peer conversation with clear sender identity:
 * - Sent messages: RIGHT side (Emerald) with "You (Analyst)" & timestamp.
 * - Received messages: LEFT side (Dark Slate) with Client Name, @ID & timestamp.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { 
  MessageSquare, 
  Send, 
  Lock, 
  Briefcase, 
  User, 
  Inbox, 
  Search, 
  Plus, 
  RefreshCw,
  CheckCheck,
  ShieldCheck
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";
import { toast } from "sonner";

interface Contact {
  id: string;
  name: string;
  user_slug: string;
  public_user_id: string;
  role: string;
  unread_count: number;
  last_message: string | null;
  last_message_at: string | null;
}

interface MessageItem {
  id: string;
  sender_id: string;
  sender_public_id?: string;
  sender_name: string;
  recipient_id: string;
  recipient_public_id?: string;
  body: string;
  is_mine: boolean;
  is_read?: boolean;
  created_at: string;
  timestamp?: string;
}

export default function AnalystMessages() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [selectedSlug, setSelectedSlug] = useState<string>("");
  const [targetInput, setTargetInput] = useState<string>("");
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // 1. Load conversation contacts scoped by the logged-in analyst
  const { 
    data: contacts = [], 
    isLoading: loadingContacts, 
    refetch: refetchContacts 
  } = useQuery<Contact[]>({
    queryKey: ["analyst-contacts", user?.id],
    queryFn: async () => {
      const res = await api.get<any>("/direct-messages/contacts");
      const list = Array.isArray(res.data) ? res.data : (res.data?.contacts || []);
      return list.map((c: any) => ({
        id: String(c.id || c.user_id),
        name: c.name || c.full_name || c.public_user_id || "Client",
        user_slug: c.user_slug || c.public_user_id || String(c.user_id),
        public_user_id: c.public_user_id || c.user_slug || String(c.user_id),
        role: c.role || "client",
        unread_count: c.unread_count || 0,
        last_message: c.last_message || null,
        last_message_at: c.last_message_at || null,
      }));
    },
    refetchInterval: 5000,
  });

  // Auto-select first contact if none chosen yet
  useEffect(() => {
    if (!selectedSlug && contacts.length > 0 && contacts[0]) {
      setSelectedSlug(contacts[0].user_slug);
    }
  }, [contacts, selectedSlug]);

  const activeContact = contacts.find(
    (c) => c.user_slug.toLowerCase() === selectedSlug.toLowerCase() ||
           c.public_user_id.toLowerCase() === selectedSlug.toLowerCase()
  ) || (
    selectedSlug ? {
      id: selectedSlug,
      name: selectedSlug,
      user_slug: selectedSlug,
      public_user_id: selectedSlug,
      role: "client",
      unread_count: 0,
      last_message: null,
      last_message_at: null,
    } : null
  );

  // 2. Load conversation history strictly for the selected peer
  const { 
    data: messages = [], 
    isLoading: loadingMessages, 
    refetch: refetchMessages 
  } = useQuery<MessageItem[]>({
    queryKey: ["analyst-messages", user?.id, selectedSlug],
    queryFn: async () => {
      if (!selectedSlug) return [];
      const res = await api.get<any>(`/direct-messages/${encodeURIComponent(selectedSlug)}`);
      const list = Array.isArray(res.data) ? res.data : (res.data?.messages || []);
      return list.map((m: any) => ({
        id: String(m.id),
        sender_id: String(m.sender_id),
        sender_public_id: m.sender_public_id,
        sender_name: m.sender_name || m.sender_public_id || "User",
        recipient_id: String(m.recipient_id),
        recipient_public_id: m.recipient_public_id,
        body: m.body,
        is_mine: Boolean(m.is_mine ?? m.is_me ?? (user?.id && String(m.sender_id) === String(user.id))),
        is_read: Boolean(m.is_read),
        created_at: m.created_at,
        timestamp: m.timestamp || new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }));
    },
    enabled: Boolean(selectedSlug),
    refetchInterval: 3000,
  });

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMutation = useMutation({
    mutationFn: async (bodyText: string) => {
      if (!selectedSlug) throw new Error("No contact selected");
      const { data } = await api.post(`/direct-messages/${encodeURIComponent(selectedSlug)}`, {
        body: bodyText,
      });
      return data;
    },
    onSuccess: () => {
      setInput("");
      refetchMessages();
      refetchContacts();
      queryClient.invalidateQueries({ queryKey: ["analyst-messages", user?.id, selectedSlug] });
      queryClient.invalidateQueries({ queryKey: ["analyst-contacts", user?.id] });
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || err?.message || "Failed to send message");
    },
  });

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !selectedSlug || sendMutation.isPending) return;
    sendMutation.mutate(input.trim());
  };

  const handleStartNewChat = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    const clean = targetInput.trim().replace(/^@/, "");
    setSelectedSlug(clean);
    setTargetInput("");
    toast.info(`Opened conversation with @${clean}`);
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex gap-4 animate-in fade-in duration-300 font-sans">
      
      {/* ── Left Sidebar (Conversations Roster) ───────────────────────── */}
      <div className="w-80 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shrink-0">
        <div className="p-4 border-b border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-bold text-slate-100 text-sm flex items-center gap-2">
              <Briefcase size={16} className="text-emerald-400" />
              Case Communications
            </h2>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => refetchContacts()}
              className="h-7 w-7 p-0 text-slate-400 hover:text-slate-200"
              title="Refresh contacts"
            >
              <RefreshCw size={13} />
            </Button>
          </div>
          <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2">
            <p className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Active Analyst</p>
            <p className="text-xs text-emerald-400 font-mono font-medium truncate mt-0.5">
              {user?.public_user_id || "analyst-session"}
            </p>
          </div>

          {/* Quick search / Start conversation */}
          <form onSubmit={handleStartNewChat} className="flex gap-1.5">
            <Input
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter User ID (slug)..."
              leftIcon={<Search size={13} />}
              className="h-8 text-xs bg-slate-950 border-slate-800"
            />
            <Button type="submit" size="sm" className="h-8 px-2.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold shrink-0">
              <Plus size={14} />
            </Button>
          </form>
        </div>

        {/* Contacts list */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-2 space-y-1">
          {loadingContacts ? (
            <div className="p-8 text-center"><Spinner label="Loading contacts..." /></div>
          ) : contacts.length === 0 ? (
            <div className="p-6 text-center text-slate-500 text-xs">
              <Inbox size={28} className="mx-auto mb-2 text-slate-600" />
              <p className="font-medium text-slate-400">No active conversations</p>
              <p className="text-[10px] text-slate-600 mt-1">
                Enter a client's User ID above or wait for users to message you from their portal.
              </p>
            </div>
          ) : (
            contacts.map((contact) => {
              const isActive = selectedSlug.toLowerCase() === contact.user_slug.toLowerCase() ||
                               selectedSlug.toLowerCase() === contact.public_user_id.toLowerCase();
              return (
                <div 
                  key={contact.id} 
                  className={`p-3 rounded-xl cursor-pointer transition ${
                    isActive ? "bg-emerald-500/10 border border-emerald-500/40 shadow-sm" : "hover:bg-slate-800/50"
                  }`}
                  onClick={() => setSelectedSlug(contact.user_slug)}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-200 truncate">{contact.name}</span>
                    <span className="text-[10px] text-slate-500 shrink-0 ml-2">
                      {contact.last_message_at ? new Date(contact.last_message_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ""}
                    </span>
                  </div>
                  <div className="flex items-center justify-between mt-0.5">
                    <p className="text-[11px] font-mono text-cyan-400">@{contact.user_slug}</p>
                    {contact.unread_count > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[9px] font-bold bg-emerald-500 text-slate-950">
                        {contact.unread_count}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 truncate mt-1">
                    {contact.last_message || "No messages yet"}
                  </p>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* ── Right Panel (Active Conversation) ────────────────────────── */}
      <div className="flex-1 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        {activeContact ? (
          <>
            {/* Conversation Header */}
            <div className="h-16 border-b border-slate-800 px-6 flex items-center justify-between bg-slate-950/60 shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-emerald-400 font-bold text-sm">
                  <User size={18} />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 text-sm flex items-center gap-2">
                    <span>{activeContact.name}</span>
                    <span className="font-mono text-xs text-cyan-400">(@{activeContact.user_slug})</span>
                    <ShieldCheck size={14} className="text-emerald-400" />
                  </h3>
                  <span className="text-xs text-slate-400 font-medium capitalize flex items-center gap-1.5 mt-0.5">
                    <Lock size={11} className="text-emerald-400" /> Secure peer channel with client
                  </span>
                </div>
              </div>
              <span className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
                <Lock size={12} className="text-emerald-400" /> Authorized Scoped Session
              </span>
            </div>

            {/* Messages Feed */}
            <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-slate-950/40">
              {loadingMessages ? (
                <div className="h-full flex items-center justify-center"><Spinner label="Loading conversation..." /></div>
              ) : messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs text-center">
                  <MessageSquare size={36} className="mx-auto text-slate-600 mb-2" />
                  <p className="text-slate-400 font-medium">No messages exchanged yet</p>
                  <p className="text-slate-600 mt-1 max-w-sm">
                    Send a message below to start communicating with @{activeContact.user_slug}.
                  </p>
                </div>
              ) : (
                messages.map((m) => {
                  const isOutgoing = m.is_mine;

                  if (isOutgoing) {
                    // ── SENDER (OUTGOING) -> RIGHT SIDE ──
                    return (
                      <div key={m.id} className="flex justify-end w-full">
                        <div className="flex flex-col items-end max-w-[80%] sm:max-w-md">
                          {/* Identity & Timestamp Header */}
                          <div className="flex items-center gap-1.5 mb-1 px-1">
                            <span className="text-[11px] font-bold text-emerald-400">You (Analyst)</span>
                            <span className="text-[10px] text-slate-400 font-mono">{m.timestamp}</span>
                          </div>

                          {/* Message Bubble: Emerald */}
                          <div className="p-3.5 rounded-2xl rounded-tr-xs bg-gradient-to-br from-emerald-600 to-emerald-500 text-slate-950 font-medium text-xs leading-relaxed shadow-lg shadow-emerald-950/20">
                            <p className="whitespace-pre-wrap break-words">{m.body}</p>
                          </div>

                          {/* Status Indicator */}
                          <div className="flex items-center gap-1 mt-1 px-1 text-[10px] text-slate-400">
                            <CheckCheck size={12} className={m.is_read ? "text-emerald-400" : "text-slate-400"} />
                            <span>{m.is_read ? "Read" : "Sent"}</span>
                          </div>
                        </div>
                      </div>
                    );
                  } else {
                    // ── RECEIVER (INCOMING) -> LEFT SIDE ──
                    const displayName = m.sender_name || activeContact.name || "Client";
                    const displaySlug = m.sender_public_id || activeContact.user_slug;

                    return (
                      <div key={m.id} className="flex justify-start w-full">
                        <div className="flex flex-col items-start max-w-[80%] sm:max-w-md">
                          {/* Identity & Timestamp Header */}
                          <div className="flex items-center gap-2 mb-1 px-1">
                            <div className="w-5 h-5 rounded-full bg-slate-800 border border-emerald-500/40 flex items-center justify-center text-[10px] font-bold text-emerald-400">
                              {displayName.charAt(0).toUpperCase()}
                            </div>
                            <span className="text-[11px] font-bold text-slate-200">
                              {displayName}
                            </span>
                            <span className="text-[10px] font-mono text-cyan-400/80">
                              @{displaySlug}
                            </span>
                            <span className="text-[10px] text-slate-400 font-mono">
                              {m.timestamp}
                            </span>
                          </div>

                          {/* Message Bubble: Dark Slate */}
                          <div className="p-3.5 rounded-2xl rounded-tl-xs bg-slate-800/90 border border-slate-700/80 text-slate-100 text-xs leading-relaxed shadow-lg shadow-black/30">
                            <p className="whitespace-pre-wrap break-words">{m.body}</p>
                          </div>

                          {/* Client verification status */}
                          <div className="flex items-center gap-1 mt-1 px-1 text-[10px] text-slate-400">
                            <ShieldCheck size={11} className="text-cyan-400" />
                            <span>Client Session</span>
                          </div>
                        </div>
                      </div>
                    );
                  }
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input Bar */}
            <form onSubmit={handleSend} className="p-4 border-t border-slate-800 bg-slate-950/60 flex gap-2 shrink-0">
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={`Send message to @${activeContact.user_slug}...`}
                className="bg-slate-900 border-slate-800 text-xs"
                disabled={sendMutation.isPending}
              />
              <Button 
                type="submit" 
                isLoading={sendMutation.isPending} 
                disabled={!input.trim() || sendMutation.isPending}
                className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold px-4"
              >
                <Send size={14} />
              </Button>
            </form>
          </>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 text-sm">
            <Briefcase size={40} className="text-slate-600 mb-2" />
            <p className="text-slate-300 font-medium">Select or start a conversation</p>
            <p className="text-xs text-slate-500 mt-1">Enter a client User ID on the left to coordinate on security incidents.</p>
          </div>
        )}
      </div>
    </div>
  );
}

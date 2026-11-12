/**
 * CyberGuard AI — Page 18: Personal Direct Messages
 * ============================================================================
 * Direct, end-to-end scoped messaging between individual users and verified
 * analysts using exact public User IDs. Backed by PostgreSQL direct_messages.
 * Messages are strictly isolated per peer conversation with clear sender identity:
 * - Sent messages: RIGHT side (Cyan) with "You" & timestamp.
 * - Received messages: LEFT side (Dark Slate) with Sender Name, @ID & timestamp.
 */

import { useState, useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { 
  MessageSquare, 
  Send, 
  User, 
  Plus,
  RefreshCw,
  ShieldCheck,
  CheckCheck,
  Search,
  Lock
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { toast } from "sonner";
import { useAuth } from "@/auth/AuthProvider";
import { api } from "@/lib/api";

interface ContactItem {
  user_id: string;
  id?: string;
  public_user_id: string;
  user_slug?: string;
  full_name: string;
  name?: string;
  email: string;
  role: string;
  last_message?: string;
  last_message_at?: string;
  unread_count: number;
}

interface DirectMessageItem {
  id: string;
  sender_id: string;
  sender_public_id?: string;
  sender_name?: string;
  recipient_id: string;
  recipient_public_id?: string;
  body: string;
  is_me: boolean;
  is_mine?: boolean;
  is_read: boolean;
  created_at: string;
  timestamp: string;
}

export default function PersonalMessages() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const targetUserParam = searchParams.get("user") || "";
  const evidenceRef = searchParams.get("ref");

  const [targetInput, setTargetInput] = useState("");
  const [activeRecipient, setActiveRecipient] = useState(targetUserParam);
  const [inputText, setInputText] = useState(
    evidenceRef ? `Hello! I would like your analysis on evidence item ${evidenceRef}.` : ""
  );
  const [isSending, setIsSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Sync state if URL search param changes externally
  useEffect(() => {
    if (targetUserParam && targetUserParam !== activeRecipient) {
      setActiveRecipient(targetUserParam);
    }
  }, [targetUserParam]);

  // 1. Load conversation contacts scoped by the logged-in user
  const { data: contacts = [], refetch: refetchContacts } = useQuery<ContactItem[]>({
    queryKey: ["direct-message-contacts", user?.id],
    queryFn: async () => {
      const res = await api.get<any>("/direct-messages/contacts");
      const list = Array.isArray(res.data) ? res.data : (res.data?.contacts || []);
      return list.map((c: any) => ({
        user_id: String(c.user_id || c.id),
        id: String(c.id || c.user_id),
        public_user_id: c.public_user_id || c.user_slug || String(c.user_id),
        user_slug: c.user_slug || c.public_user_id || String(c.user_id),
        full_name: c.full_name || c.name || "Analyst",
        name: c.name || c.full_name || "Analyst",
        email: c.email || "",
        role: c.role || "analyst",
        last_message: c.last_message || undefined,
        last_message_at: c.last_message_at || undefined,
        unread_count: c.unread_count || 0,
      }));
    },
    refetchInterval: 5_000,
  });

  // Select first contact if none selected or if previous contact does not exist for this account
  useEffect(() => {
    if (contacts.length > 0 && contacts[0]) {
      const exists = contacts.some(
        (c) => c.public_user_id.toLowerCase() === activeRecipient.toLowerCase() ||
               (c.user_slug && c.user_slug.toLowerCase() === activeRecipient.toLowerCase())
      );
      if (!activeRecipient || !exists) {
        const firstSlug = contacts[0].public_user_id;
        setActiveRecipient(firstSlug);
        setSearchParams({ user: firstSlug });
      }
    }
  }, [contacts, activeRecipient, setSearchParams]);

  const activeContact = contacts.find(
    (c) => c.public_user_id.toLowerCase() === activeRecipient.toLowerCase() ||
           (c.user_slug && c.user_slug.toLowerCase() === activeRecipient.toLowerCase())
  );

  // 2. Load conversation history strictly for the selected peer
  const { data: messageHistory = [], refetch: refetchMessages, isLoading: isMessagesLoading } = useQuery<DirectMessageItem[]>({
    queryKey: ["direct-messages", user?.id, activeRecipient],
    queryFn: async () => {
      if (!activeRecipient) return [];
      const res = await api.get<DirectMessageItem[]>(`/direct-messages/${encodeURIComponent(activeRecipient)}`);
      return res.data || [];
    },
    enabled: Boolean(activeRecipient),
    refetchInterval: 3_000,
  });

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messageHistory]);

  const handleSelectContact = (slug: string) => {
    setActiveRecipient(slug);
    setSearchParams({ user: slug });
  };

  const handleStartConversation = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    const clean = targetInput.trim().replace(/^@/, "");
    setActiveRecipient(clean);
    setSearchParams({ user: clean });
    setTargetInput("");
    toast.info(`Opened conversation with @${clean}`);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || !activeRecipient || isSending) return;

    const textToSend = inputText.trim();
    setIsSending(true);

    try {
      await api.post(`/direct-messages/${encodeURIComponent(activeRecipient)}`, { body: textToSend });
      setInputText("");
      refetchMessages();
      refetchContacts();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to deliver message. Verify the recipient User ID.");
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex gap-4 animate-in fade-in duration-300 font-sans">
      
      {/* ── Left Sidebar (Conversations Roster) ───────────────────────── */}
      <div className="w-80 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shrink-0">
        <div className="p-4 border-b border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-bold text-slate-100 text-sm flex items-center gap-2">
              <MessageSquare size={16} className="text-cyan-400" />
              Direct Messages
            </h2>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => refetchContacts()}
              className="h-7 w-7 p-0 text-slate-400 hover:text-slate-200"
              title="Refresh messages"
            >
              <RefreshCw size={13} />
            </Button>
          </div>
          <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2">
            <p className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Logged In As</p>
            <p className="text-xs text-cyan-400 font-mono font-medium truncate mt-0.5">
              {user?.public_user_id || "loading..."}
            </p>
          </div>

          <form onSubmit={handleStartConversation} className="flex gap-1.5">
            <Input
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter User ID (slug)..."
              leftIcon={<Search size={13} />}
              className="bg-slate-950 border-slate-800 text-xs h-8 text-slate-200"
            />
            <Button type="submit" size="sm" className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-2.5 h-8 shrink-0">
              <Plus size={14} />
            </Button>
          </form>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-2 space-y-1">
          {contacts.length === 0 ? (
            <div className="text-center py-12 px-4">
              <User className="w-8 h-8 text-slate-700 mx-auto mb-2" />
              <p className="text-xs font-semibold text-slate-400">No conversations yet</p>
              <p className="text-[11px] text-slate-500 mt-1">
                Enter an analyst or colleague's public User ID above to start an authorized conversation.
              </p>
            </div>
          ) : (
            contacts.map((c) => {
              const isSelected = activeRecipient.toLowerCase() === c.public_user_id.toLowerCase();
              return (
                <div
                  key={c.user_id}
                  onClick={() => handleSelectContact(c.public_user_id)}
                  className={`p-3 rounded-xl cursor-pointer transition flex items-center justify-between ${
                    isSelected ? "bg-cyan-500/10 border border-cyan-500/40 shadow-sm" : "hover:bg-slate-800/50"
                  }`}
                >
                  <div className="space-y-0.5 max-w-[190px]">
                    <p className="text-xs font-bold text-slate-200 truncate">{c.full_name}</p>
                    <p className="text-[10px] text-cyan-400/90 font-mono truncate">@{c.public_user_id}</p>
                    {c.last_message && (
                      <p className="text-[11px] text-slate-400 truncate mt-1">{c.last_message}</p>
                    )}
                  </div>
                  {c.unread_count > 0 && (
                    <span className="h-5 w-5 rounded-full bg-cyan-500 text-slate-950 font-bold text-[10px] flex items-center justify-center">
                      {c.unread_count}
                    </span>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* ── Main Chat Window ─────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 font-bold text-sm">
              <User size={18} />
            </div>
            <div>
              <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                <span>{activeContact?.full_name || activeRecipient || "Select a Conversation"}</span>
                {activeRecipient && (
                  <span className="font-mono text-xs text-cyan-400">(@{activeRecipient})</span>
                )}
                {activeRecipient && <ShieldCheck size={14} className="text-emerald-400" />}
              </h3>
              <p className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                <Lock size={11} className="text-cyan-400" />
                {activeRecipient ? "End-to-end authorized channel — scoped exclusively to this peer" : "No active peer selected"}
              </p>
            </div>
          </div>
        </div>

        {/* Message Stream */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4 bg-slate-950/40">
          {!activeRecipient ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8">
              <MessageSquare className="w-10 h-10 text-slate-700 mb-2" />
              <p className="text-sm font-bold text-slate-300">No Active Chat</p>
              <p className="text-xs text-slate-500 mt-1 max-w-sm">
                Select an existing conversation on the left or enter a public User ID to start messaging.
              </p>
            </div>
          ) : isMessagesLoading ? (
            <div className="h-full flex items-center justify-center text-xs text-slate-500">
              Loading encrypted conversation history...
            </div>
          ) : messageHistory.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8">
              <MessageSquare className="w-10 h-10 text-slate-700 mb-2" />
              <p className="text-sm font-bold text-slate-300">Beginning of Conversation</p>
              <p className="text-xs text-slate-500 mt-1 max-w-sm">
                No messages exchanged with <span className="text-cyan-400 font-mono">@{activeRecipient}</span> yet. Send your first message below.
              </p>
            </div>
          ) : (
            messageHistory.map((msg) => {
              // Strict sender determination based on logged-in user profile & public user ID
              const isOutgoing = Boolean(
                (user?.public_user_id && msg.sender_public_id && msg.sender_public_id.toLowerCase() === user.public_user_id.toLowerCase()) ||
                (user?.id && String(msg.sender_id) === String(user.id)) ||
                msg.is_me ||
                msg.is_mine
              );

              if (isOutgoing) {
                // ── SENDER (OUTGOING) -> RIGHT SIDE ──
                return (
                  <div key={msg.id} className="flex justify-end w-full">
                    <div className="flex flex-col items-end max-w-[80%] sm:max-w-md">
                      {/* Identity & Timestamp Header */}
                      <div className="flex items-center gap-1.5 mb-1 px-1">
                        <span className="text-[11px] font-bold text-cyan-400">You</span>
                        <span className="text-[10px] text-slate-400 font-mono">{msg.timestamp}</span>
                      </div>

                      {/* Message Bubble: Cyan */}
                      <div className="p-3.5 rounded-2xl rounded-tr-xs bg-gradient-to-br from-cyan-500 to-cyan-600 text-slate-950 font-medium text-xs leading-relaxed shadow-lg shadow-cyan-950/20">
                        <p className="whitespace-pre-wrap break-words">{msg.body}</p>
                      </div>

                      {/* Read status */}
                      <div className="flex items-center gap-1 mt-1 px-1 text-[10px] text-slate-400">
                        <CheckCheck size={12} className={msg.is_read ? "text-cyan-400" : "text-slate-400"} />
                        <span>{msg.is_read ? "Read" : "Sent"}</span>
                      </div>
                    </div>
                  </div>
                );
              } else {
                // ── RECEIVER (INCOMING) -> LEFT SIDE ──
                const displayName = msg.sender_name || activeContact?.full_name || "Analyst";
                const displaySlug = msg.sender_public_id || activeRecipient;

                return (
                  <div key={msg.id} className="flex justify-start w-full">
                    <div className="flex flex-col items-start max-w-[80%] sm:max-w-md">
                      {/* Identity & Timestamp Header */}
                      <div className="flex items-center gap-2 mb-1 px-1">
                        <div className="w-5 h-5 rounded-full bg-slate-800 border border-cyan-500/40 flex items-center justify-center text-[10px] font-bold text-cyan-400">
                          {displayName.charAt(0).toUpperCase()}
                        </div>
                        <span className="text-[11px] font-bold text-slate-200">
                          {displayName}
                        </span>
                        <span className="text-[10px] font-mono text-cyan-400/80">
                          @{displaySlug}
                        </span>
                        <span className="text-[10px] text-slate-400 font-mono">
                          {msg.timestamp}
                        </span>
                      </div>

                      {/* Message Bubble: Dark Slate */}
                      <div className="p-3.5 rounded-2xl rounded-tl-xs bg-slate-800/90 border border-slate-700/80 text-slate-100 text-xs leading-relaxed shadow-lg shadow-black/30">
                        <p className="whitespace-pre-wrap break-words">{msg.body}</p>
                      </div>

                      {/* Peer badge */}
                      <div className="flex items-center gap-1 mt-1 px-1 text-[10px] text-slate-400">
                        <ShieldCheck size={11} className="text-emerald-400" />
                        <span>Verified Channel</span>
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
        <div className="p-3 border-t border-slate-800 bg-slate-950/80">
          <form onSubmit={handleSend} className="flex gap-2">
            <Input
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder={activeRecipient ? `Message @${activeRecipient}...` : "Select a recipient first"}
              disabled={!activeRecipient || isSending}
              className="bg-slate-900 border-slate-800 text-xs h-10 text-slate-200"
            />
            <Button
              type="submit"
              disabled={!activeRecipient || !inputText.trim() || isSending}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 h-10"
            >
              <Send size={14} />
            </Button>
          </form>
        </div>
      </div>

    </div>
  );
}

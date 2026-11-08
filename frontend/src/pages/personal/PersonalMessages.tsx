/**
 * CyberGuard AI — Page 18: Personal Direct Messages
 * ============================================================================
 * Direct, end-to-end scoped messaging between individual users and verified
 * analysts using exact public User IDs. Backed by PostgreSQL direct_messages.
 */

import { useState, useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { 
  MessageSquare, 
  Send, 
  Search, 
  User, 
  Plus,
  RefreshCw,
  ShieldCheck,
  CheckCheck
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { useAuth } from "@/auth/AuthProvider";
import { api } from "@/lib/api";

interface ContactItem {
  user_id: string;
  public_user_id: string;
  full_name: string;
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
  recipient_id: string;
  recipient_public_id?: string;
  body: string;
  is_me: boolean;
  is_read: boolean;
  created_at: string;
  timestamp: string;
}

export default function PersonalMessages() {
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const targetUserParam = searchParams.get("user") || "";
  const evidenceRef = searchParams.get("ref");

  const [targetInput, setTargetInput] = useState(targetUserParam);
  const [activeRecipient, setActiveRecipient] = useState(targetUserParam);
  const [inputText, setInputText] = useState(
    evidenceRef ? `Hello! I would like your analysis on evidence item ${evidenceRef}.` : ""
  );
  const [isSending, setIsSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // 1. Load conversation contacts
  const { data: contacts = [], refetch: refetchContacts } = useQuery<ContactItem[]>({
    queryKey: ["direct-message-contacts"],
    queryFn: async () => {
      const res = await api.get<ContactItem[]>("/direct-messages/contacts");
      return res.data || [];
    },
    refetchInterval: 15_000,
  });

  // Select first contact if none selected and contacts exist
  useEffect(() => {
    if (!activeRecipient && contacts.length > 0 && contacts[0]) {
      setActiveRecipient(contacts[0].public_user_id);
    }
  }, [contacts, activeRecipient]);

  // 2. Load conversation history with active recipient
  const { data: messageHistory = [], refetch: refetchMessages, isLoading: isMessagesLoading } = useQuery<DirectMessageItem[]>({
    queryKey: ["direct-messages", activeRecipient],
    queryFn: async () => {
      if (!activeRecipient) return [];
      const res = await api.get<DirectMessageItem[]>(`/direct-messages/${activeRecipient}`);
      return res.data || [];
    },
    enabled: Boolean(activeRecipient),
    refetchInterval: 5_000,
  });

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messageHistory]);

  const handleStartConversation = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    setActiveRecipient(targetInput.trim());
    toast.info(`Opened conversation with ${targetInput.trim()}`);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || !activeRecipient || isSending) return;

    const textToSend = inputText.trim();
    setIsSending(true);

    try {
      await api.post(`/direct-messages/${activeRecipient}`, { body: textToSend });
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
    <div className="h-[calc(100vh-8rem)] flex gap-4 animate-in fade-in duration-300">
      
      {/* ── Left Sidebar (Conversations Roster) ───────────────────────── */}
      <div className="w-80 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shrink-0">
        <div className="p-4 border-b border-slate-800">
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
            >
              <RefreshCw size={13} />
            </Button>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">Your ID: <span className="text-cyan-400 font-mono">{user?.public_user_id || "loading..."}</span></p>

          <form onSubmit={handleStartConversation} className="mt-3 flex gap-1.5">
            <Input
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter User ID (slug)..."
              className="bg-slate-950 border-slate-800 text-xs h-8 text-slate-200"
            />
            <Button type="submit" size="sm" className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-2.5 h-8">
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
            contacts.map((c) => (
              <div
                key={c.user_id}
                onClick={() => setActiveRecipient(c.public_user_id)}
                className={`p-3 rounded-xl cursor-pointer transition flex items-center justify-between ${activeRecipient === c.public_user_id ? "bg-cyan-500/10 border border-cyan-500/30" : "hover:bg-slate-800/40"}`}
              >
                <div className="space-y-0.5 max-w-[190px]">
                  <p className="text-xs font-bold text-slate-200 truncate">{c.full_name}</p>
                  <p className="text-[10px] text-slate-500 font-mono truncate">{c.public_user_id}</p>
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
            ))
          )}
        </div>
      </div>

      {/* ── Main Chat Window ─────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 font-bold text-xs">
              <User size={16} />
            </div>
            <div>
              <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                {activeRecipient || "Select a Conversation"}
                {activeRecipient && <ShieldCheck size={14} className="text-emerald-400" />}
              </h3>
              <p className="text-[11px] text-slate-400">
                {activeRecipient ? "Authorized direct peer-to-peer session" : "No active peer selected"}
              </p>
            </div>
          </div>
        </div>

        {/* Message Stream */}
        <div className="flex-1 p-4 overflow-y-auto space-y-3 bg-slate-950/30">
          {!activeRecipient ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8">
              <MessageSquare className="w-10 h-10 text-slate-700 mb-2" />
              <p className="text-sm font-bold text-slate-300">No Active Chat</p>
              <p className="text-xs text-slate-500 mt-1 max-w-sm">
                Select an existing conversation on the left or enter a public User ID to start messaging.
              </p>
            </div>
          ) : messageHistory.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8">
              <MessageSquare className="w-10 h-10 text-slate-700 mb-2" />
              <p className="text-sm font-bold text-slate-300">Beginning of Conversation</p>
              <p className="text-xs text-slate-500 mt-1 max-w-sm">
                No messages exchanged with {activeRecipient} yet. Send your first message below.
              </p>
            </div>
          ) : (
            messageHistory.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col max-w-lg ${msg.is_me ? "ml-auto items-end" : "items-start"}`}
              >
                <div
                  className={`p-3 rounded-2xl text-xs leading-relaxed ${msg.is_me ? "bg-cyan-500 text-slate-950 font-medium rounded-tr-sm" : "bg-slate-800 text-slate-100 border border-slate-700/60 rounded-tl-sm"}`}
                >
                  <p className="whitespace-pre-wrap">{msg.body}</p>
                </div>
                <div className="flex items-center gap-1 mt-1 px-1 text-[10px] text-slate-500">
                  <span>{msg.timestamp}</span>
                  {msg.is_me && (
                    <CheckCheck size={12} className={msg.is_read ? "text-cyan-400" : "text-slate-500"} />
                  )}
                </div>
              </div>
            ))
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/80">
          <form onSubmit={handleSend} className="flex gap-2">
            <Input
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder={activeRecipient ? `Message ${activeRecipient}...` : "Select a recipient first"}
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

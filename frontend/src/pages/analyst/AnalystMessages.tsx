/**
 * CyberGuard AI — Page 31: Analyst Secure Messages
 * ============================================================================
 * Case communications and direct conversations between verified analysts
 * and authorized case participants/clients backed by persistent database storage.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { MessageSquare, Send, Lock, Briefcase, User, Inbox } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { useAuth } from "@/auth/AuthProvider";
import { toast } from "sonner";

interface Contact {
  id: string;
  name: string;
  user_slug: string;
  role: string;
  unread_count: number;
  last_message: string | null;
  last_message_at: string | null;
}

interface MessageItem {
  id: string;
  sender_id: string;
  sender_name: string;
  recipient_id: string;
  body: string;
  is_mine: boolean;
  created_at: string;
}

export default function AnalystMessages() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  const [input, setInput] = useState("");

  const { data: contactsData, isLoading: loadingContacts } = useQuery<{ contacts: Contact[] }>({
    queryKey: ["analyst-contacts"],
    queryFn: async () => {
      const { data } = await api.get<{ contacts: Contact[] }>("/direct-messages/contacts");
      return data;
    },
    refetchInterval: 8000,
  });

  const activeContact = selectedContact || (contactsData?.contacts && contactsData.contacts[0]) || null;

  const { data: messagesData, isLoading: loadingMessages } = useQuery<{ messages: MessageItem[] }>({
    queryKey: ["analyst-messages", activeContact?.user_slug],
    queryFn: async () => {
      if (!activeContact) return { messages: [] };
      const { data } = await api.get<{ messages: MessageItem[] }>(`/direct-messages/${activeContact.user_slug}`);
      return data;
    },
    enabled: !!activeContact,
    refetchInterval: 4000,
  });

  const sendMutation = useMutation({
    mutationFn: async (bodyText: string) => {
      if (!activeContact) throw new Error("No contact selected");
      const { data } = await api.post(`/direct-messages/${activeContact.user_slug}`, {
        body: bodyText,
      });
      return data;
    },
    onSuccess: () => {
      setInput("");
      queryClient.invalidateQueries({ queryKey: ["analyst-messages", activeContact?.user_slug] });
      queryClient.invalidateQueries({ queryKey: ["analyst-contacts"] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to send message");
    },
  });

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !activeContact) return;
    sendMutation.mutate(input.trim());
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex gap-4 animate-in fade-in duration-300">
      <div className="w-80 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800">
          <h2 className="font-bold text-slate-100 text-sm flex items-center gap-2">
            <Briefcase size={16} className="text-emerald-400" />
            Case Communications
          </h2>
          <p className="text-[11px] text-slate-400">Direct encrypted channels with authorized contacts</p>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
          {loadingContacts ? (
            <div className="p-8 text-center"><Spinner label="Loading contacts..." /></div>
          ) : !contactsData?.contacts || contactsData.contacts.length === 0 ? (
            <div className="p-6 text-center text-slate-500 text-xs">
              <Inbox size={28} className="mx-auto mb-2 text-slate-600" />
              <p>No active case channels found.</p>
              <p className="text-[10px] text-slate-600 mt-1">Once clients or team members message you, channels will list here.</p>
            </div>
          ) : (
            contactsData.contacts.map((contact) => (
              <div 
                key={contact.id} 
                className={`p-3 cursor-pointer transition ${activeContact?.id === contact.id ? "bg-slate-800/70" : "hover:bg-slate-800/30"}`}
                onClick={() => setSelectedContact(contact)}
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200">{contact.name}</span>
                  <span className="text-[10px] text-slate-500">
                    {contact.last_message_at ? formatRelativeTime(contact.last_message_at) : ""}
                  </span>
                </div>
                <p className="text-[11px] font-mono text-cyan-400">@{contact.user_slug}</p>
                <p className="text-xs text-slate-400 truncate mt-1">
                  {contact.last_message || "No messages yet"}
                </p>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="flex-1 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        {activeContact ? (
          <>
            <div className="h-16 border-b border-slate-800 px-6 flex items-center justify-between bg-slate-950/40">
              <div>
                <h3 className="font-bold text-slate-100 text-sm">{activeContact.name} (@{activeContact.user_slug})</h3>
                <span className="text-xs text-emerald-400 font-medium capitalize">{activeContact.role}</span>
              </div>
              <span className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
                <Lock size={12} className="text-emerald-400" /> Secure Scoped Channel
              </span>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {loadingMessages ? (
                <div className="h-full flex items-center justify-center"><Spinner label="Loading conversation..." /></div>
              ) : !messagesData?.messages || messagesData.messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs text-center">
                  <MessageSquare size={36} className="mx-auto text-slate-600 mb-2" />
                  <p className="text-slate-400 font-medium">No messages exchanged yet</p>
                  <p className="text-slate-600 mt-1">Send a message below to coordinate regarding cases or forensic deliverables.</p>
                </div>
              ) : (
                messagesData.messages.map((m) => (
                  <div key={m.id} className={`flex ${m.is_mine ? "justify-end" : "justify-start"}`}>
                    <div
                      className={`max-w-md rounded-2xl p-3.5 text-xs ${
                        m.is_mine
                          ? "bg-emerald-600 text-slate-950 font-medium"
                          : "bg-slate-950 border border-slate-800 text-slate-200"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-4 mb-1">
                        <span className={`text-[10px] font-bold ${m.is_mine ? "text-slate-950" : "text-cyan-400 font-mono"}`}>
                          {m.is_mine ? "You" : m.sender_name}
                        </span>
                        <span className={`text-[10px] ${m.is_mine ? "text-slate-900/70" : "text-slate-500"}`}>
                          {formatRelativeTime(m.created_at)}
                        </span>
                      </div>
                      <p className="break-words leading-relaxed">{m.body}</p>
                    </div>
                  </div>
                ))
              )}
            </div>

            <form onSubmit={handleSend} className="p-4 border-t border-slate-800 bg-slate-950/40 flex gap-2">
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={`Send encrypted message to @${activeContact.user_slug}...`}
                className="bg-slate-900 border-slate-800 text-xs"
              />
              <Button 
                type="submit" 
                isLoading={sendMutation.isPending} 
                className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold"
              >
                <Send size={14} />
              </Button>
            </form>
          </>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 text-sm">
            <Briefcase size={40} className="text-slate-600 mb-2" />
            <p>Select a contact or client from the left pane to open the investigation channel.</p>
          </div>
        )}
      </div>
    </div>
  );
}

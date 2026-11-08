/**
 * CyberGuard AI — Page 31: Analyst Secure Messages
 * ============================================================================
 * Case communications and direct conversations between verified analysts
 * and authorized case participants/clients.
 */

import { useState } from "react";
import { MessageSquare, Send, Paperclip, Lock, Briefcase, User } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { toast } from "sonner";
import { useAuth } from "@/auth/AuthProvider";

export default function AnalystMessages() {
  const { user } = useAuth();
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState([
    {
      id: "1",
      sender: "riya-user-000184",
      isMe: false,
      text: "Hi Aarav, thanks for taking on case CASE-2026-0042. I have uploaded the raw headers of the email.",
      timestamp: "09:35 AM",
    },
    {
      id: "2",
      sender: "me",
      isMe: true,
      text: "Received! I verified the SHA-256 hash and completed the domain reputation check. The phishing email connects to a malicious IP. A formal report is ready on the workbench.",
      timestamp: "10:14 AM",
    },
  ]);

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    setMessages((prev) => [
      ...prev,
      {
        id: Date.now().toString(),
        sender: user?.public_user_id || "me",
        isMe: true,
        text: input.trim(),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
    setInput("");
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex gap-4 animate-in fade-in duration-300">
      <div className="w-80 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800">
          <h2 className="font-bold text-slate-100 text-sm flex items-center gap-2">
            <Briefcase size={16} className="text-emerald-400" />
            Case Conversations
          </h2>
          <p className="text-[11px] text-slate-400">Scoped strictly to assigned cases</p>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
          <div className="p-3 bg-slate-800/40 cursor-pointer">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-slate-200">CASE-2026-0042</span>
              <span className="text-[10px] text-slate-500">10:14 AM</span>
            </div>
            <p className="text-[11px] font-mono text-cyan-400">riya-user-000184</p>
            <p className="text-xs text-slate-400 truncate mt-1">Received! I verified the SHA-256 hash...</p>
          </div>
        </div>
      </div>

      <div className="flex-1 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="h-16 border-b border-slate-800 px-6 flex items-center justify-between bg-slate-950/40">
          <div>
            <h3 className="font-bold text-slate-100 text-sm">CASE-2026-0042 • Client: riya-user-000184</h3>
            <span className="text-xs text-emerald-400 font-medium">Targeted Spearphishing Forensics</span>
          </div>
          <span className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
            <Lock size={12} className="text-emerald-400" /> Case-Scoped Channel
          </span>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.map((m) => (
            <div key={m.id} className={`flex ${m.isMe ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-md rounded-2xl p-3.5 text-xs ${
                  m.isMe
                    ? "bg-emerald-600 text-slate-950 font-medium"
                    : "bg-slate-950 border border-slate-800 text-slate-200"
                }`}
              >
                <div className="flex items-center justify-between gap-4 mb-1">
                  <span className={`text-[10px] font-bold ${m.isMe ? "text-slate-950" : "text-cyan-400 font-mono"}`}>
                    {m.isMe ? "You (Analyst)" : m.sender}
                  </span>
                  <span className={`text-[10px] ${m.isMe ? "text-slate-900/60" : "text-slate-500"}`}>{m.timestamp}</span>
                </div>
                <p>{m.text}</p>
              </div>
            </div>
          ))}
        </div>

        <form onSubmit={handleSend} className="p-4 border-t border-slate-800 bg-slate-950/50 flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Send message to client..."
            className="bg-slate-900 border-slate-800 text-xs text-slate-100 focus:border-emerald-500"
          />
          <Button type="submit" className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold px-4">
            <Send size={16} />
          </Button>
        </form>
      </div>
    </div>
  );
}

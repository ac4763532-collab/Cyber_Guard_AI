/**
 * CyberGuard AI — Page 18: Personal Direct Messages
 * ============================================================================
 * Direct, end-to-end scoped messaging between individual users and verified
 * analysts using exact public User IDs. Does not mix with Room or Case scopes.
 */

import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { 
  MessageSquare, 
  Send, 
  Paperclip, 
  ShieldCheck, 
  Lock, 
  Search, 
  User, 
  Plus 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { useAuth } from "@/auth/AuthProvider";

interface ChatMessage {
  id: string;
  sender: string;
  isMe: boolean;
  text: string;
  timestamp: string;
}

export default function PersonalMessages() {
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const targetUserParam = searchParams.get("user") || "aarav-analyst-000042";

  const [activeContact, setActiveContact] = useState({
    name: "Aarav Mehta (Analyst)",
    public_id: targetUserParam,
    status: "online",
  });

  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "1",
      sender: "aarav-analyst-000042",
      isMe: false,
      text: "Hello! I received your inquiry regarding the flagged email EML-001. I have reviewed the DMARC record and can confirm it's an impersonation attack.",
      timestamp: "10:15 AM",
    },
    {
      id: "2",
      sender: "me",
      isMe: true,
      text: "Thanks Aarav! Should I report this domain to our registrar as well?",
      timestamp: "10:18 AM",
    },
  ]);

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const newMsg: ChatMessage = {
      id: Date.now().toString(),
      sender: user?.public_user_id || "me",
      isMe: true,
      text: input.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, newMsg]);
    setInput("");
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex gap-4 animate-in fade-in duration-300">
      
      {/* ── Left Sidebar (Conversations) ──────────────────────────────── */}
      <div className="w-80 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="font-bold text-slate-100 text-sm flex items-center gap-2">
              <MessageSquare size={16} className="text-cyan-400" />
              Direct Messages
            </h2>
            <p className="text-[11px] text-slate-400">Scoped to your verified ID</p>
          </div>
          <Button size="sm" variant="ghost" className="h-8 w-8 p-0 text-slate-400 hover:text-cyan-400">
            <Plus size={18} />
          </Button>
        </div>

        <div className="p-3 border-b border-slate-800/60">
          <Input
            placeholder="Search by User ID..."
            className="bg-slate-950 border-slate-800 text-xs h-8"
          />
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
          <div
            onClick={() => setActiveContact({ name: "Aarav Mehta (Analyst)", public_id: "aarav-analyst-000042", status: "online" })}
            className="p-3 hover:bg-slate-800/50 cursor-pointer transition bg-slate-800/30"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-slate-200">Aarav Mehta</span>
              <span className="text-[10px] text-slate-500">10:18 AM</span>
            </div>
            <p className="text-[11px] font-mono text-cyan-400 mt-0.5">aarav-analyst-000042</p>
            <p className="text-xs text-slate-400 truncate mt-1">Thanks Aarav! Should I report this...</p>
          </div>
        </div>
      </div>

      {/* ── Right Chat Area ───────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        
        {/* Chat Header */}
        <div className="h-16 border-b border-slate-800 px-6 flex items-center justify-between bg-slate-950/40">
          <div>
            <h3 className="font-bold text-slate-100 text-sm">{activeContact.name}</h3>
            <span className="text-xs font-mono text-cyan-400">{activeContact.public_id}</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Lock size={14} className="text-emerald-400" />
            <span>Encrypted Direct Scope</span>
          </div>
        </div>

        {/* Messages Stream */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.map((m) => (
            <div key={m.id} className={`flex ${m.isMe ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-md rounded-2xl p-3.5 text-xs ${
                  m.isMe
                    ? "bg-cyan-600 text-slate-950 font-medium"
                    : "bg-slate-950 border border-slate-800 text-slate-200"
                }`}
              >
                <div className="flex items-center justify-between gap-4 mb-1">
                  <span className={`text-[10px] font-bold ${m.isMe ? "text-slate-950" : "text-cyan-400 font-mono"}`}>
                    {m.isMe ? "You" : m.sender}
                  </span>
                  <span className={`text-[10px] ${m.isMe ? "text-slate-900/60" : "text-slate-500"}`}>{m.timestamp}</span>
                </div>
                <p>{m.text}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Input Form */}
        <form onSubmit={handleSend} className="p-4 border-t border-slate-800 bg-slate-950/50 flex gap-2">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => toast.info("Evidence attachment vault opened")}
            className="text-slate-400 hover:text-cyan-400"
          >
            <Paperclip size={18} />
          </Button>
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type a message or attach evidence..."
            className="bg-slate-900 border-slate-800 text-xs text-slate-100 focus:border-cyan-500"
          />
          <Button type="submit" className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4">
            <Send size={16} />
          </Button>
        </form>
      </div>

    </div>
  );
}

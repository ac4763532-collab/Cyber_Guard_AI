/**
 * CyberGuard AI — Page 16: AI Security Assistant
 * ============================================================================
 * Evidence-grounded conversational assistant that explains security findings,
 * maps threats to MITRE ATT&CK, and answers queries without fabricating data.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { 
  Bot, 
  Send, 
  Sparkles, 
  ShieldAlert, 
  AlertTriangle, 
  RefreshCw,
  Terminal,
  ShieldCheck 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";
import { api } from "@/lib/api";

interface Message {
  id: string;
  sender: "user" | "assistant";
  content: string;
  timestamp: string;
  evidenceRef?: string;
}

export default function AIAssistant() {
  const [input, setInput] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // 1. Check provider availability
  const { data: statusData, isLoading: isStatusLoading } = useQuery({
    queryKey: ["assistant-status"],
    queryFn: async () => {
      const res = await api.get<{ provider: string; available: boolean; message: string }>("/assistant/status");
      return res.data;
    },
  });

  // 2. Load stored conversation history
  const { data: storedMessages = [], refetch: refetchMessages } = useQuery<Message[]>({
    queryKey: ["assistant-messages"],
    queryFn: async () => {
      const res = await api.get<Message[]>("/assistant/messages");
      return res.data || [];
    },
  });

  const [messages, setMessages] = useState<Message[]>([]);

  useEffect(() => {
    if (storedMessages.length > 0) {
      setMessages(storedMessages);
    }
  }, [storedMessages]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isThinking]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isThinking) return;

    const userText = input.trim();
    const userMsg: Message = {
      id: Date.now().toString(),
      sender: "user",
      content: userText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsThinking(true);

    try {
      const { data } = await api.post("/assistant/messages", { message: userText });
      const assistantMsg: Message = {
        id: (Date.now() + 1).toString(),
        sender: "assistant",
        content: data.reply,
        timestamp: data.timestamp || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        evidenceRef: data.evidence_ref,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || "AI provider unavailable. Configure a supported provider to enable AI assistance.";
      setMessages((prev) => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          sender: "assistant",
          content: errorMsg,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setIsThinking(false);
    }
  };

  const providerAvailable = statusData?.available ?? false;

  return (
    <div className="h-[calc(100vh-8rem)] flex flex-col space-y-4 animate-in fade-in duration-300">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Bot size={22} />
          </div>
          <div>
            <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">
              Evidence-Grounded Intelligence
            </span>
            <h1 className="text-xl font-black text-slate-100 tracking-tight flex items-center gap-2">
              CyberGuard AI Security Assistant
              <span className={`h-2 w-2 rounded-full ${providerAvailable ? "bg-emerald-500 animate-pulse" : "bg-amber-500"}`} />
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refetchMessages()}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            <RefreshCw size={14} className="mr-1" /> Refresh History
          </Button>
        </div>
      </div>

      {/* Honest Provider Status Banner */}
      {!providerAvailable && !isStatusLoading && (
        <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-center gap-3 text-xs text-amber-300">
          <AlertTriangle size={18} className="shrink-0 text-amber-400" />
          <span>AI provider unavailable. Configure a supported provider to enable AI assistance.</span>
        </div>
      )}

      {/* Conversation Stream */}
      <Card className="flex-1 bg-slate-900 border-slate-800 flex flex-col overflow-hidden">
        <CardContent className="flex-1 p-4 overflow-y-auto space-y-4">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8">
              <Bot className="w-12 h-12 text-slate-700 mb-3" />
              <p className="text-sm font-bold text-slate-300">Evidence-Grounded Assistant</p>
              <p className="text-xs text-slate-500 mt-1 max-w-sm">
                Ask questions about your enrolled devices, flagged emails, authentication events, or MITRE ATT&CK mappings. Telemetry is verified against database records.
              </p>
            </div>
          ) : (
            messages.map((m) => (
              <div
                key={m.id}
                className={`flex gap-3 max-w-3xl ${m.sender === "user" ? "ml-auto flex-row-reverse" : ""}`}
              >
                <div
                  className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 text-xs font-bold ${m.sender === "user" ? "bg-cyan-500 text-slate-950" : "bg-slate-800 text-cyan-400 border border-cyan-500/30"}`}
                >
                  {m.sender === "user" ? "You" : <Sparkles size={16} />}
                </div>

                <div className="space-y-1">
                  <div
                    className={`p-3.5 rounded-2xl text-xs leading-relaxed ${m.sender === "user" ? "bg-cyan-500 text-slate-950 font-medium" : "bg-slate-950 border border-slate-800 text-slate-200"}`}
                  >
                    <p className="whitespace-pre-wrap">{m.content}</p>
                    {m.evidenceRef && (
                      <div className="mt-2 pt-2 border-t border-slate-800/80 text-[10px] text-cyan-400 font-mono flex items-center gap-1.5">
                        <Terminal size={12} /> Evidence Reference: {m.evidenceRef}
                      </div>
                    )}
                  </div>
                  <span className="text-[10px] text-slate-500 block px-1">{m.timestamp}</span>
                </div>
              </div>
            ))
          )}

          {isThinking && (
            <div className="flex gap-3 max-w-3xl">
              <div className="w-8 h-8 rounded-xl bg-slate-800 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Sparkles size={16} className="animate-spin" />
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-2xl text-xs text-slate-400 flex items-center gap-2">
                <span>Analyzing authorized database telemetry...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </CardContent>

        {/* Input Bar */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/70">
          <form onSubmit={handleSend} className="flex gap-2">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about your security posture, device findings, or suspicious activity..."
              className="bg-slate-900 border-slate-800 text-xs h-10 text-slate-200"
              disabled={isThinking}
            />
            <Button
              type="submit"
              disabled={!input.trim() || isThinking}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4"
            >
              <Send size={14} />
            </Button>
          </form>
        </div>
      </Card>
    </div>
  );
}

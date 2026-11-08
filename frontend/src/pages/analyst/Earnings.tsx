/**
 * CyberGuard AI — Page 35: Earnings & Payments
 * ============================================================================
 * Review case milestones, paid payouts, available balances, and Stripe/payment
 * provider invoices. Never stores raw card numbers.
 */

import { DollarSign, CreditCard, Download, ArrowUpRight, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function Earnings() {
  const transactions = [
    {
      id: "TX-9041",
      case_id: "CASE-2026-0042",
      description: "Spearphishing Forensics Milestone",
      amount: "+$350.00",
      date: "2026-11-08",
      status: "completed",
    },
    {
      id: "TX-8920",
      case_id: "CASE-2026-0038",
      description: "C2 Traffic Triage & Mitigation Report",
      amount: "+$500.00",
      date: "2026-11-04",
      status: "completed",
    },
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 35 • Payouts & Balance
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Earnings & Payments
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Track case compensation, settlement invoices, and automated payouts.
          </p>
        </div>

        <Button
          onClick={() => toast.info("Opening secure payment provider portal...")}
          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
        >
          <CreditCard size={14} className="mr-1.5" /> Payout Settings
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs text-slate-400">Available Balance</p>
          <p className="text-2xl font-black text-emerald-400 mt-1">$2,450.00</p>
          <span className="text-[11px] text-slate-400 mt-1 block">Scheduled for direct deposit Friday</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs text-slate-400">Total Earned to Date</p>
          <p className="text-2xl font-black text-slate-100 mt-1">$14,820.00</p>
          <span className="text-[11px] text-slate-400 mt-1 block">Across 38 closed cases</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs text-slate-400">Pending Review</p>
          <p className="text-2xl font-black text-amber-400 mt-1">$350.00</p>
          <span className="text-[11px] text-slate-400 mt-1 block">1 Milestone awaiting sign-off</span>
        </Card>
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="text-base text-slate-100">Transaction History</CardTitle>
        </CardHeader>
        <CardContent className="p-0 divide-y divide-slate-800/80 font-mono text-xs">
          {transactions.map((tx) => (
            <div key={tx.id} className="p-4 flex items-center justify-between hover:bg-slate-800/30 transition">
              <div>
                <p className="font-bold text-slate-200">{tx.description}</p>
                <p className="text-[11px] text-slate-500 font-sans mt-0.5">
                  Ref: <span className="font-mono text-cyan-400">{tx.id}</span> • {tx.case_id} • {tx.date}
                </p>
              </div>
              <div className="text-right">
                <span className="text-sm font-bold text-emerald-400">{tx.amount}</span>
                <span className="text-[10px] block text-emerald-500 font-sans">Verified</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

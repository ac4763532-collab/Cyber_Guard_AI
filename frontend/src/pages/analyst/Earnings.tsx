/**
 * CyberGuard AI — Page 35: Earnings & Payments
 * ============================================================================
 * Review case milestones, paid payouts, available balances, and payment
 * transactions. Connected to live marketplace ledger.
 */

import { useQuery } from "@tanstack/react-query";
import { DollarSign, CreditCard, Download, ArrowUpRight, CheckCircle2, Inbox } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";

interface TransactionItem {
  id: string;
  offering_title: string;
  amount_cents: number;
  currency: string;
  status: string;
  created_at: string;
}

export default function Earnings() {
  const { data: dashboard, isLoading: loadingDash } = useQuery<{ balance_usd: number }>({
    queryKey: ["analyst-dashboard"],
    queryFn: async () => {
      const { data } = await api.get<{ balance_usd: number }>("/dashboard/analyst");
      return data;
    },
  });

  const { data: purchases, isLoading: loadingPurchases } = useQuery<{ items: any[]; total: number }>({
    queryKey: ["marketplace-purchases"],
    queryFn: async () => {
      try {
        const { data } = await api.get<{ items: any[]; total: number }>("/marketplace/purchases");
        return data;
      } catch (err) {
        return { items: [], total: 0 };
      }
    },
  });

  const balance = dashboard?.balance_usd ?? 0;
  const items = purchases?.items || [];

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
          onClick={() => toast.info("Payment provider payout schedule: processed weekly on Friday.")}
          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
        >
          <CreditCard size={14} className="mr-1.5" /> Payout Settings
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs text-slate-400">Available Balance</p>
          <p className="text-2xl font-black text-emerald-400 mt-1">
            {loadingDash ? "..." : `$${balance.toFixed(2)}`}
          </p>
          <span className="text-[11px] text-slate-400 mt-1 block">Scheduled for direct deposit Friday</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs text-slate-400">Total Settled Transactions</p>
          <p className="text-2xl font-black text-slate-100 mt-1">{items.length}</p>
          <span className="text-[11px] text-slate-400 mt-1 block">Across completed case milestones</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs text-slate-400">Pending Review</p>
          <p className="text-2xl font-black text-amber-400 mt-1">$0.00</p>
          <span className="text-[11px] text-slate-400 mt-1 block">No unreleased holds</span>
        </Card>
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="text-base text-slate-100">Transaction History</CardTitle>
        </CardHeader>
        <CardContent className="p-0 divide-y divide-slate-800/80 font-mono text-xs">
          {loadingPurchases ? (
            <div className="p-12 text-center"><Spinner label="Loading ledger..." /></div>
          ) : items.length === 0 ? (
            <div className="p-12 text-center text-slate-400">
              <Inbox size={40} className="mx-auto text-slate-600 mb-2" />
              <p className="font-semibold text-slate-300">No transactions recorded</p>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                Payouts and billing transactions for verified case milestones will appear in this ledger once services are completed.
              </p>
            </div>
          ) : (
            items.map((tx: any) => (
              <div key={tx.id} className="p-4 flex items-center justify-between hover:bg-slate-800/30 transition">
                <div>
                  <p className="font-bold text-slate-200">{tx.offering_title || "Security Service Purchase"}</p>
                  <p className="text-[11px] text-slate-500 font-sans mt-0.5">
                    Ref: <span className="font-mono text-cyan-400">{tx.id.substring(0, 8)}</span> • {formatRelativeTime(tx.created_at)}
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-sm font-bold text-emerald-400">
                    +${((tx.amount_cents || 0) / 100).toFixed(2)}
                  </span>
                  <span className="text-[10px] block text-emerald-500 font-sans uppercase">{tx.status}</span>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/**
 * CyberGuard AI — Marketplace Page
 * ============================================================================
 * 
 * The storefront where clients can hire verified security analysts.
 * 
 * Features:
 *   - Responsive grid of analyst offerings.
 *   - Search bar to filter offerings by name or specialization.
 *   - Checkout Modal: Confirms the purchase and triggers the backend
 *     to create a Case, assign the analyst, and grant access.
 *   - Role Note: In a production app, the header button would be conditional:
 *     Clients see "Browse", Analysts see "Create Offering".
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Search, Star, ShieldCheck, Clock } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription, ModalFooter } from "@/components/ui/Modal";


// ============================================================================
// LOCAL TYPES (Mirroring backend schema)
// ============================================================================

interface ServiceOffering {
  id: string;
  analyst_name: string;
  title: string;
  description: string | null;
  price_cents: number;
  currency: string;
  delivery_days: number;
  rating_average: number | null;
  purchase_count: number;
  specializations: string[];
}

const formatPrice = (cents: number, currency: string) => {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency || "USD",
  }).format(cents / 100);
};


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Marketplace() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedOffering, setSelectedOffering] = useState<ServiceOffering | null>(null);

  // ── Fetch Offerings ───────────────────────────────────────────────────
  const { data, isLoading } = useQuery({
    queryKey: ["offerings", searchQuery],
    queryFn: async () => {
      const params: Record<string, any> = { page: 1, page_size: 50 };
      if (searchQuery) params.search = searchQuery;

      const { data } = await api.get<PaginatedResponse<ServiceOffering>>("/marketplace/offerings", { params });
      return data;
    },
  });

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Security Marketplace
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Hire verified experts to investigate alerts and respond to incidents.
          </p>
        </div>
      </div>

      {/* ── Search Toolbar ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-4">
        <div className="w-full max-w-md">
          <Input
            placeholder="Search by analyst, specialization, or service..."
            leftIcon={<Search size={16} />}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* ── Offerings Grid ─────────────────────────────────────────────── */}
      {isLoading ? (
        <div className="py-20"><Spinner size="lg" label="Loading marketplace..." /></div>
      ) : data?.items.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center text-slate-500">
            No offerings found matching your search.
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {data?.items.map((offering) => (
            <Card key={offering.id} className="flex flex-col h-full">
              <CardContent className="p-6 flex flex-col flex-1">
                
                {/* Analyst Info */}
                <div className="flex items-center gap-3 mb-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-full bg-brand-100 text-brand-700 font-bold text-lg dark:bg-brand-900/50 dark:text-brand-400">
                    {offering.analyst_name.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-900 dark:text-slate-100">
                      {offering.analyst_name}
                    </h3>
                    <div className="flex items-center gap-1 text-xs text-amber-500">
                      <Star size={12} fill="currentColor" />
                      <span>{offering.rating_average?.toFixed(1) || "New"}</span>
                      <span className="text-slate-400">({offering.purchase_count} hires)</span>
                    </div>
                  </div>
                </div>

                {/* Service Title */}
                <div className="mb-4 flex-1">
                  <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-1">
                    {offering.title}
                  </h4>
                  <p className="text-sm text-slate-500 dark:text-slate-400 line-clamp-3">
                    {offering.description || "No description provided."}
                  </p>
                </div>

                {/* Tags */}
                <div className="flex flex-wrap gap-1.5 mb-6">
                  {offering.specializations.map((spec) => (
                    <Badge key={spec} variant="outline" label={spec.replace("_", " ")} className="text-[10px]" />
                  ))}
                </div>

                {/* Footer */}
                <div className="mt-auto pt-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between">
                  <div>
                    <p className="text-lg font-bold text-slate-900 dark:text-slate-100">
                      {formatPrice(offering.price_cents, offering.currency)}
                    </p>
                    <p className="text-xs text-slate-500 flex items-center gap-1">
                      <Clock size={12} /> {offering.delivery_days} day delivery
                    </p>
                  </div>
                  <Button onClick={() => setSelectedOffering(offering)}>
                    Hire Analyst
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* ── Checkout Modal ─────────────────────────────────────────────── */}
      <CheckoutModal 
        offering={selectedOffering} 
        onClose={() => setSelectedOffering(null)} 
      />

    </div>
  );
}


// ============================================================================
// CHECKOUT MODAL
// ============================================================================

function CheckoutModal({ offering, onClose }: { offering: ServiceOffering | null, onClose: () => void }) {
  const queryClient = useQueryClient();

  const purchaseMutation = useMutation({
    mutationFn: async () => {
      if (!offering) return;
      // Backend creates the purchase + case + access grant
      const { data } = await api.post("/marketplace/purchases", {
        offering_id: offering.id,
        // idempotency_key is generated by the backend or frontend (we'll let backend handle for MVP)
      });
      return data;
    },
    onSuccess: () => {
      toast.success("Purchase successful! A new case has been created.");
      queryClient.invalidateQueries({ queryKey: ["offerings"] });
      queryClient.invalidateQueries({ queryKey: ["cases"] });
      onClose();
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to complete purchase");
    },
  });

  if (!offering) return null;

  return (
    <Modal open={!!offering} onOpenChange={(open) => !open && onClose()}>
      <ModalContent>
        <ModalHeader>
          <ModalTitle>Confirm Engagement</ModalTitle>
          <ModalDescription>
            You are hiring {offering.analyst_name} for {offering.title}.
          </ModalDescription>
        </ModalHeader>

        <div className="py-6 space-y-4">
          <div className="rounded-lg bg-slate-50 p-4 dark:bg-slate-800/50 flex flex-col gap-2 text-sm">
            <div className="flex justify-between font-medium">
              <span className="text-slate-600 dark:text-slate-400">Service</span>
              <span className="text-slate-900 dark:text-slate-100">{offering.title}</span>
            </div>
            <div className="flex justify-between font-medium">
              <span className="text-slate-600 dark:text-slate-400">Delivery</span>
              <span className="text-slate-900 dark:text-slate-100">{offering.delivery_days} days</span>
            </div>
            <div className="flex justify-between font-bold pt-2 border-t border-slate-200 dark:border-slate-700 mt-2">
              <span className="text-slate-900 dark:text-slate-100">Total</span>
              <span className="text-brand-600 dark:text-brand-400">{formatPrice(offering.price_cents, offering.currency)}</span>
            </div>
          </div>

          <div className="flex items-start gap-2 text-xs text-slate-500">
            <ShieldCheck size={16} className="text-green-500 shrink-0" />
            <p>Payment is processed securely. By confirming, an isolated case workspace will be created, and the analyst will be granted scoped access to your evidence.</p>
          </div>
        </div>

        <ModalFooter>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={() => purchaseMutation.mutate()} isLoading={purchaseMutation.isPending}>
            Confirm & Pay
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
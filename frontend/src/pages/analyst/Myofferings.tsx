/**
 * CyberGuard AI — Analyst: My Offerings Page
 * ============================================================================
 * 
 * Allows verified analysts to create and manage their marketplace listings.
 * 
 * Features:
 *   - Lists the analyst's active and draft offerings.
 *   - "Create Offering" modal with fields for Title, Price, and Delivery.
 *   - Enforces backend validation (price must be positive, etc.)
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Briefcase, Star, Clock } from "lucide-react";
import { toast } from "sonner";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";

import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription, ModalFooter } from "@/components/ui/Modal";


// ============================================================================
// TYPES & SCHEMAS
// ============================================================================

interface ServiceOffering {
  id: string;
  title: string;
  description: string | null;
  price_cents: number;
  currency: string;
  delivery_days: number;
  status: string;
  purchase_count: number;
}

const offeringSchema = z.object({
  title: z.string().min(5, "Title must be at least 5 characters"),
  description: z.string().optional(),
  price: z.coerce.number().min(50, "Minimum price is $50"), // Price in dollars
  deliveryDays: z.coerce.number().min(1, "Delivery must be at least 1 day").max(30),
});

type OfferingFormValues = z.infer<typeof offeringSchema>;


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function MyOfferings() {
  const [isModalOpen, setIsModalOpen] = useState(false);

  // ── Fetch Analyst's Own Offerings ─────────────────────────────────────
  const { data, isLoading } = useQuery({
    queryKey: ["my-offerings"],
    queryFn: async () => {
      // In a real app, the backend uses the JWT to filter by the current analyst
      const { data } = await api.get<PaginatedResponse<ServiceOffering>>("/marketplace/offerings", {
        params: { page: 1, page_size: 50, mine: true }, // 'mine=true' tells backend to filter by JWT
      });
      return data;
    },
  });

  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            My Service Offerings
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Manage the services you offer to clients on the marketplace.
          </p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} leftIcon={<Plus size={16} />}>
          Create Offering
        </Button>
      </div>

      {/* ── Offerings List ─────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading your offerings..." /></CardContent></Card>
      ) : (!data?.items || data.items.length === 0) ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center p-12 text-center">
            <Briefcase size={48} className="text-slate-300 dark:text-slate-600 mb-4" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">No offerings yet</h3>
            <p className="mt-1 text-sm text-slate-500 max-w-sm">
              You haven't created any service offerings. Create one to start accepting clients.
            </p>
            <Button className="mt-6" onClick={() => setIsModalOpen(true)}>
              Create your first offering
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {(data?.items || []).map((offering) => (
            <Card key={offering.id}>
              <CardContent className="p-6">
                <div className="flex justify-between items-start mb-4">
                  <Badge status={offering.status} withDot />
                  <div className="flex items-center gap-1 text-xs text-amber-500 bg-amber-50 px-2 py-1 rounded-md dark:bg-amber-900/30">
                    <Star size={12} fill="currentColor" />
                    <span>{offering.purchase_count} hires</span>
                  </div>
                </div>
                <h3 className="font-semibold text-slate-900 dark:text-slate-100 mb-2">{offering.title}</h3>
                <p className="text-sm text-slate-500 line-clamp-2 mb-4">{offering.description}</p>
                
                <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
                  <span className="font-bold text-lg text-slate-900 dark:text-slate-100">
                    ${(offering.price_cents / 100).toFixed(2)}
                  </span>
                  <span className="text-xs text-slate-500 flex items-center gap-1">
                    <Clock size={12} /> {offering.delivery_days} days
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <CreateOfferingModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </div>
  );
}


// ============================================================================
// CREATE OFFERING MODAL
// ============================================================================

function CreateOfferingModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();

  const form = useForm<OfferingFormValues>({
    resolver: zodResolver(offeringSchema),
    defaultValues: {
      title: "",
      description: "",
      price: 499,
      deliveryDays: 3,
    },
  });

  const mutation = useMutation({
    mutationFn: async (values: OfferingFormValues) => {
      // Convert dollars back to cents for the backend
      const payload = {
        title: values.title,
        description: values.description,
        price_cents: Math.round(values.price * 100),
        currency: "USD",
        delivery_days: values.deliveryDays,
        specializations: ["incident_response"], // Hardcoded for MVP
      };
      const { data } = await api.post("/marketplace/offerings", payload);
      return data;
    },
    onSuccess: () => {
      toast.success("Offering created successfully!");
      queryClient.invalidateQueries({ queryKey: ["my-offerings"] });
      queryClient.invalidateQueries({ queryKey: ["offerings"] }); // Update public marketplace
      onClose();
      form.reset();
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to create offering");
    },
  });

  return (
    <Modal open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <ModalContent>
        <form onSubmit={form.handleSubmit((data) => mutation.mutate(data))}>
          <ModalHeader>
            <ModalTitle>Create Service Offering</ModalTitle>
            <ModalDescription>
              Define a new service package for clients to purchase.
            </ModalDescription>
          </ModalHeader>

          <div className="py-6 space-y-4">
            <Input
              label="Service Title"
              placeholder="e.g. Phishing Investigation"
              {...form.register("title")}
              error={form.formState.errors.title?.message}
            />
            
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Description</label>
              <textarea
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                rows={3}
                placeholder="What does this service include?"
                {...form.register("description")}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <Input
                label="Price (USD)"
                type="number"
                {...form.register("price")}
                error={form.formState.errors.price?.message}
              />
              <Input
                label="Delivery (Days)"
                type="number"
                {...form.register("deliveryDays")}
                error={form.formState.errors.deliveryDays?.message}
              />
            </div>
          </div>

          <ModalFooter>
            <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
            <Button type="submit" isLoading={mutation.isPending}>Publish Offering</Button>
          </ModalFooter>
        </form>
      </ModalContent>
    </Modal>
  );
}
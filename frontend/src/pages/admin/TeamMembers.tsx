/**
 * CyberGuard AI — Org Admin: Team Members Page
 * ============================================================================
 * 
 * Allows Company Admins to manage their employees.
 * 
 * Features:
 *   - Lists all users in the organization.
 *   - Shows their role (Owner, Admin, Member) and status.
 *   - "Invite Member" modal to send an email invitation.
 *   - Revoke access / remove members (UI only for MVP, backend handles
 *     the actual soft-delete and access revocation).
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Users, Mail, Shield, MoreHorizontal } from "lucide-react";
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
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";
import { formatDate } from "@/lib/utils";


// ============================================================================
// TYPES & SCHEMAS
// ============================================================================

interface TeamMember {
  id: string;
  email: string;
  full_name: string | null;
  role: "owner" | "admin" | "member";
  status: "active" | "pending" | "suspended";
  joined_at: string | null;
}

const inviteSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  role: z.enum(["admin", "member"]),
});

type InviteFormValues = z.infer<typeof inviteSchema>;


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function TeamMembers() {
  const [isModalOpen, setIsModalOpen] = useState(false);

  // ── Fetch Team ────────────────────────────────────────────────────────
  const { data, isLoading } = useQuery({
    queryKey: ["team-members"],
    queryFn: async () => {
      // Backend resolves 'current' to the org the user is actively logged into
      const { data } = await api.get<PaginatedResponse<TeamMember>>("/organizations/current/members", {
        params: { page: 1, page_size: 50 },
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
            Team Members
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Manage who has access to your organization's security workspace.
          </p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} leftIcon={<Plus size={16} />}>
          Invite Member
        </Button>
      </div>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading team..." /></CardContent></Card>
      ) : (!data?.items || data.items.length === 0) ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center p-12 text-center">
            <Users size={48} className="text-slate-300 dark:text-slate-600 mb-4" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">No team members</h3>
            <p className="mt-1 text-sm text-slate-500 max-w-sm">
              You are the only member of this organization. Invite your team to start monitoring their devices.
            </p>
            <Button className="mt-6" onClick={() => setIsModalOpen(true)}>
              Invite your first member
            </Button>
          </CardContent>
        </Card>
      ) : (
        <TableWrapper>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden md:table-cell">Joined</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.items || []).map((member) => (
                <TableRow key={member.id}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-xs font-bold text-brand-700 dark:bg-brand-900/50 dark:text-brand-400">
                        {member.full_name?.charAt(0).toUpperCase() || member.email.charAt(0).toUpperCase()}
                      </div>
                      <div className="flex flex-col">
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {member.full_name || "Invited User"}
                        </span>
                        <span className="text-xs text-slate-500">{member.email}</span>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge 
                      status={member.role === "owner" ? "acknowledged" : member.role === "admin" ? "investigating" : "resolved"} 
                      label={member.role} 
                    />
                  </TableCell>
                  <TableCell>
                    {member.status === "active" ? (
                      <span className="text-sm font-medium text-green-600 dark:text-green-400">Active</span>
                    ) : member.status === "pending" ? (
                      <span className="text-sm font-medium text-amber-600 dark:text-amber-400">Pending Invite</span>
                    ) : (
                      <span className="text-sm font-medium text-red-600 dark:text-red-400">Suspended</span>
                    )}
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-slate-500">
                    {member.joined_at ? formatDate(member.joined_at) : "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm">
                      <MoreHorizontal size={16} />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableWrapper>
      )}

      <InviteMemberModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </div>
  );
}


// ============================================================================
// INVITE MEMBER MODAL
// ============================================================================

function InviteMemberModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();

  const form = useForm<InviteFormValues>({
    resolver: zodResolver(inviteSchema),
    defaultValues: {
      email: "",
      role: "member",
    },
  });

  const mutation = useMutation({
    mutationFn: async (values: InviteFormValues) => {
      const { data } = await api.post("/organizations/current/invitations", values);
      return data;
    },
    onSuccess: () => {
      toast.success("Invitation sent successfully!");
      queryClient.invalidateQueries({ queryKey: ["team-members"] });
      onClose();
      form.reset();
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to send invitation");
    },
  });

  return (
    <Modal open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <ModalContent>
        <form onSubmit={form.handleSubmit((data) => mutation.mutate(data))}>
          <ModalHeader>
            <ModalTitle>Invite Team Member</ModalTitle>
            <ModalDescription>
              They will receive an email with instructions to join your organization.
            </ModalDescription>
          </ModalHeader>

          <div className="py-6 space-y-4">
            <Input
              label="Email Address"
              type="email"
              placeholder="colleague@company.com"
              leftIcon={<Mail size={16} />}
              {...form.register("email")}
              error={form.formState.errors.email?.message}
            />

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                Role
              </label>
              <select
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                {...form.register("role")}
              >
                <option value="member">Member (Monitors own devices)</option>
                <option value="admin">Admin (Can manage team & settings)</option>
              </select>
            </div>
          </div>

          <ModalFooter>
            <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
            <Button type="submit" isLoading={mutation.isPending} leftIcon={<Shield size={16} />}>
              Send Invitation
            </Button>
          </ModalFooter>
        </form>
      </ModalContent>
    </Modal>
  );
}
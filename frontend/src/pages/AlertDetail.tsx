/**
 * CyberGuard AI — Alert Detail Page
 * ============================================================================
 * Detailed inspection of an alert, raw event context, correlated findings,
 * and direct investigation / escalation action buttons.
 */

import { useParams, useNavigate, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ShieldAlert, CheckCircle, XCircle, Clock, Cpu } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { SecurityAlert } from "@/types";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { formatDate, formatRelativeTime } from "@/lib/utils";

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: alert, isLoading, isError } = useQuery<SecurityAlert>({
    queryKey: ["alert", id],
    queryFn: async () => {
      const res = await api.get(`/alerts/${id}`);
      return res.data;
    },
    enabled: !!id,
  });

  const acknowledgeMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/alerts/${id}/acknowledge`);
    },
    onSuccess: () => {
      toast.success("Alert acknowledged");
      queryClient.invalidateQueries({ queryKey: ["alert", id] });
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to acknowledge alert");
    },
  });

  const dismissMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/alerts/${id}/dismiss`);
    },
    onSuccess: () => {
      toast.success("Alert dismissed");
      queryClient.invalidateQueries({ queryKey: ["alert", id] });
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to dismiss alert");
    },
  });

  if (isLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Spinner size="lg" className="text-cyan-400" />
      </div>
    );
  }

  if (isError || !alert) {
    return (
      <div className="p-8 text-center">
        <h2 className="text-xl font-bold text-red-400">Alert Not Found</h2>
        <p className="mt-2 text-slate-400">The requested alert could not be loaded.</p>
        <Button className="mt-4" onClick={() => navigate("/alerts")}>
          Back to Alerts
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/alerts")}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Alerts
        </Button>
        <span className="text-sm text-slate-500 font-mono">{alert.id}</span>
      </div>

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-slate-100">{alert.title}</h1>
            <Badge variant={alert.severity as any}>{alert.severity}</Badge>
            <Badge variant="outline">{alert.status}</Badge>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Detected {formatRelativeTime(alert.created_at)} ({formatDate(alert.created_at)})
          </p>
        </div>

        <div className="flex items-center gap-2">
          {alert.status === "new" && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => acknowledgeMutation.mutate()}
              isLoading={acknowledgeMutation.isPending}
            >
              <CheckCircle className="h-4 w-4 mr-2 text-cyan-400" />
              Acknowledge
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => dismissMutation.mutate()}
            isLoading={dismissMutation.isPending}
          >
            <XCircle className="h-4 w-4 mr-2 text-slate-400" />
            Dismiss
          </Button>
          <Link to={`/incidents`}>
            <Button variant="primary" size="sm">
              <ShieldAlert className="h-4 w-4 mr-2" />
              Escalate to Incident
            </Button>
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Alert Summary & Context</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-slate-300 leading-relaxed">{alert.description || "No description provided."}</p>
            
            <div className="rounded-lg bg-slate-900/60 p-4 border border-slate-800">
              <h4 className="text-xs uppercase tracking-wider text-cyan-400 font-semibold mb-2">
                Detection Details
              </h4>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-slate-500">Source ID:</span>{" "}
                  <span className="text-slate-200 font-mono text-xs">{alert.source_id || "Unassigned"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Category:</span>{" "}
                  <span className="text-slate-200">{alert.category || "General"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Workspace:</span>{" "}
                  <span className="text-slate-200 font-mono text-xs">{alert.workspace_id}</span>
                </div>
                <div>
                  <span className="text-slate-500">Occurrences:</span>{" "}
                  <span className="text-slate-200">{alert.occurrence_count || 1}</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>AI Correlation & Agents</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div className="flex items-start gap-3">
              <Cpu className="h-5 w-5 text-cyan-400 mt-0.5" />
              <div>
                <p className="font-medium text-slate-200">AI Threat Analyst</p>
                <p className="text-xs text-slate-400">
                  {alert.finding_ids?.length ? `${alert.finding_ids.length} correlated findings.` : "Evaluated by detection pipeline."}
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Clock className="h-5 w-5 text-blue-400 mt-0.5" />
              <div>
                <p className="font-medium text-slate-200">MITRE ATT&CK Techniques</p>
                <p className="text-xs text-slate-400 font-mono">
                  {alert.mitre_techniques?.length ? alert.mitre_techniques.join(", ") : "T1110.001 (Password Guessing)"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

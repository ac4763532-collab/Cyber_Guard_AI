/**
 * CyberGuard AI — Security Event Details Drawer
 * ============================================================================
 * Production-quality Security Activity Details interface.
 * 
 * Provides dual viewing modes:
 *   - Simple View: For ordinary computer users (6 core questions:
 *     What happened, Who was involved, Where, When, Why it matters, What to do).
 *   - Analyst View: For cybersecurity professionals (forensic properties,
 *     MITRE ATT&CK mapping with evidence rationale, decoded logon/status codes,
 *     and raw payload with copy control).
 */

import React, { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  User,
  MapPin,
  Clock,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Laptop,
  Terminal,
  FileText,
  RefreshCw,
} from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { toast } from "sonner";
import type { EventExplanationResponse } from "@/types/eventExplanation";

interface SecurityEventDetailsDrawerProps {
  eventId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

export function SecurityEventDetailsDrawer({
  eventId,
  isOpen,
  onClose,
}: SecurityEventDetailsDrawerProps) {
  const [viewMode, setViewMode] = useState<"simple" | "analyst">("simple");
  const [isRawExpanded, setIsRawExpanded] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  // Fetch enriched explanation from backend
  const {
    data: eventData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<EventExplanationResponse>({
    queryKey: ["event-explanation", eventId],
    queryFn: async () => {
      if (!eventId) throw new Error("No event ID provided");
      const res = await api.get<EventExplanationResponse>(`/events/${eventId}/explanation`);
      return res.data;
    },
    enabled: Boolean(isOpen && eventId),
    staleTime: 30_000,
  });

  const handleCopyPayload = () => {
    if (!eventData?.analyst_view.raw_payload) return;
    navigator.clipboard.writeText(
      JSON.stringify(eventData.analyst_view.raw_payload, null, 2)
    );
    setCopied(true);
    toast.success("Original event payload copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  if (!isOpen) return null;

  // Helper badge renderers
  const renderDefinitionBadge = (status: string) => {
    switch (status) {
      case "verified":
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
            title="Verified against the official CyberGuard Windows Event Knowledge Base"
          >
            <CheckCircle2 size={11} /> Verified Definition
          </span>
        );
      case "partially_verified":
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30"
            title="Baseline properties identified; supplementary fields pending verification"
          >
            <AlertTriangle size={11} /> Partially Verified
          </span>
        );
      case "unknown_definition":
      default:
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 border border-slate-700"
            title="This event ID is awaiting knowledge-base indexing; original record preserved intact"
          >
            <HelpCircle size={11} /> Definition Catalog Pending
          </span>
        );
    }
  };

  const renderAssessmentBadge = (assessment: string) => {
    switch (assessment) {
      case "suspicious":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/40">
            <ShieldAlert size={11} /> Suspicious
          </span>
        );
      case "unusual":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/20 text-amber-300 border border-amber-500/40">
            <AlertTriangle size={11} /> Unusual
          </span>
        );
      case "normal":
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            <ShieldCheck size={11} /> Normal Activity
          </span>
        );
    }
  };

  const renderThreatBadge = (threat: string) => {
    if (threat === "confirmed_threat") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-600/30 text-rose-200 border border-rose-500">
          <ShieldAlert size={11} /> Threat Detected
        </span>
      );
    }
    if (threat === "under_investigation") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/20 text-amber-300 border border-amber-500/30">
          <Clock size={11} /> Under Investigation
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800/80 text-slate-400 border border-slate-700/60">
        No Threat Established
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm transition-opacity animate-in fade-in duration-200"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-over Drawer (Responsive: full-width on mobile, 680px-740px on desktop) */}
      <div className="fixed inset-y-0 right-0 flex max-w-full">
        <div className="w-full sm:w-[680px] lg:w-[740px] max-w-full bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col h-full animate-in slide-in-from-right duration-300">
          
          {/* Fixed Header */}
          <div className="p-5 border-b border-slate-800 bg-slate-950/80 flex-shrink-0">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1.5 flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                    <Activity size={13} className="text-cyan-400" /> Security Activity Details
                  </span>
                  {eventData?.original_event_id && (
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      Event ID {eventData.original_event_id}
                    </span>
                  )}
                  {eventData && renderDefinitionBadge(eventData.definition_status)}
                </div>

                <h2 className="text-xl font-bold text-slate-100 leading-snug truncate">
                  {isLoading ? "Retrieving Security Event Details..." : eventData?.title || "Security Event"}
                </h2>

                {eventData?.short_description && (
                  <p className="text-xs text-slate-400 line-clamp-2">
                    {eventData.short_description}
                  </p>
                )}
              </div>

              <button
                type="button"
                onClick={onClose}
                className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 flex-shrink-0"
                title="Close (Esc)"
              >
                <X size={18} />
              </button>
            </div>

            {/* Badges and Device Metadata */}
            {eventData && (
              <div className="flex items-center gap-2 mt-3 pt-3 border-t border-slate-800/60 flex-wrap">
                <Badge
                  severity={eventData.severity}
                  variant="severity"
                  className="text-[10px] uppercase font-bold"
                />
                {renderAssessmentBadge(eventData.assessment)}
                {renderThreatBadge(eventData.threat_status)}
                <span className="text-xs text-slate-400 font-mono ml-auto">
                  {eventData.device_name}
                </span>
              </div>
            )}
          </div>

          {/* Independently Scrollable Drawer Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5">
            {isLoading ? (
              <div className="space-y-4 py-8">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 animate-pulse space-y-3">
                  <div className="h-4 bg-slate-800 rounded w-1/3" />
                  <div className="h-3 bg-slate-800/60 rounded w-2/3" />
                  <div className="h-3 bg-slate-800/40 rounded w-1/2" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="h-20 bg-slate-950/60 border border-slate-800 rounded-xl animate-pulse" />
                  <div className="h-20 bg-slate-950/60 border border-slate-800 rounded-xl animate-pulse" />
                </div>
                <div className="h-32 bg-slate-950/60 border border-slate-800 rounded-xl animate-pulse" />
              </div>
            ) : isError || !eventData ? (
              <div className="p-8 text-center space-y-3 rounded-xl bg-rose-500/10 border border-rose-500/30">
                <AlertTriangle size={36} className="mx-auto text-rose-400" />
                <h3 className="text-base font-semibold text-rose-300">Unable to retrieve security event details</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  {error instanceof Error ? error.message : "The server could not provide an explanation for this event record."}
                </p>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => refetch()}
                  className="mt-2 border-slate-700 text-slate-300 hover:bg-slate-800 text-xs"
                >
                  <RefreshCw size={12} className="mr-1.5" /> Try Again
                </Button>
              </div>
            ) : (
              <>
                {/* Event Summary: Clean Two-Column Information Layout */}
                <div className="rounded-xl bg-slate-950/80 border border-slate-800 p-4">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-3 border-b border-slate-800/60 pb-1.5">
                    Event Summary
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-y-3 gap-x-6 text-xs">
                    {/* Device */}
                    <div className="flex items-start justify-between border-b border-slate-800/40 pb-2">
                      <span className="text-slate-400 font-medium">Device:</span>
                      <span className="font-semibold text-slate-200 text-right truncate max-w-[200px]" title={eventData.device_name}>
                        {eventData.device_name}
                      </span>
                    </div>

                    {/* Account */}
                    <div className="flex items-start justify-between border-b border-slate-800/40 pb-2">
                      <span className="text-slate-400 font-medium">Account:</span>
                      <span className="font-semibold text-slate-200 text-right font-mono">
                        {eventData.simple_view.who.account_name ? (
                          eventData.simple_view.who.account_name
                        ) : (
                          <span className="text-slate-500 italic font-sans">Not recorded</span>
                        )}
                      </span>
                    </div>

                    {/* Event Date & Time */}
                    <div className="flex items-start justify-between border-b border-slate-800/40 pb-2">
                      <span className="text-slate-400 font-medium">Date & Time:</span>
                      <span className="font-semibold text-slate-200 text-right font-mono text-[11px]">
                        {eventData.simple_view.when.timestamp_formatted}
                      </span>
                    </div>

                    {/* Event ID */}
                    <div className="flex items-start justify-between border-b border-slate-800/40 pb-2">
                      <span className="text-slate-400 font-medium">Event ID:</span>
                      <span className="font-semibold text-cyan-300 text-right font-mono">
                        {eventData.original_event_id || "N/A"}
                      </span>
                    </div>

                    {/* Category */}
                    <div className="flex items-start justify-between">
                      <span className="text-slate-400 font-medium">Category:</span>
                      <span className="font-semibold text-slate-200 text-right capitalize">
                        {eventData.category}
                      </span>
                    </div>

                    {/* Severity */}
                    <div className="flex items-start justify-between">
                      <span className="text-slate-400 font-medium">Severity:</span>
                      <Badge
                        severity={eventData.severity}
                        variant="severity"
                        className="text-[10px] uppercase font-bold"
                      />
                    </div>
                  </div>
                </div>

                {/* View Mode Toggle */}
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <div className="inline-flex p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                    <button
                      type="button"
                      onClick={() => setViewMode("simple")}
                      className={`px-3 py-1.5 rounded-md font-semibold transition-all flex items-center gap-1.5 ${
                        viewMode === "simple"
                          ? "bg-cyan-500 text-slate-950 shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <FileText size={13} /> Simple View
                    </button>
                    <button
                      type="button"
                      onClick={() => setViewMode("analyst")}
                      className={`px-3 py-1.5 rounded-md font-semibold transition-all flex items-center gap-1.5 ${
                        viewMode === "analyst"
                          ? "bg-cyan-500 text-slate-950 shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Terminal size={13} /> Analyst View
                    </button>
                  </div>

                  <span className="text-[11px] text-slate-500">
                    {viewMode === "simple" ? "Plain-language guide for all users" : "Technical & forensic evidence"}
                  </span>
                </div>

                {/* VIEW MODE 1: SIMPLE VIEW (6 Essential Sections) */}
                {viewMode === "simple" && (
                  <div className="space-y-4 text-xs">
                    
                    {/* 1. What happened? */}
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2">
                      <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                        <Activity size={16} />
                        <h3>1. What happened?</h3>
                      </div>
                      <p className="text-slate-200 leading-relaxed text-xs sm:text-[13px]">
                        {eventData.simple_view.what_happened}
                      </p>
                    </div>

                    {/* 2. Who was involved? */}
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2.5">
                      <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                        <User size={16} />
                        <h3>2. Who was involved?</h3>
                      </div>
                      <p className="text-slate-300 leading-relaxed">
                        {eventData.simple_view.who.explanation}
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-slate-800/60 font-mono text-[11px]">
                        <div>
                          <span className="text-slate-500 font-sans">Account Name:</span>{" "}
                          <span className="text-slate-200 font-semibold">
                            {eventData.simple_view.who.account_name || "Not specified in record"}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-sans">Account Role:</span>{" "}
                          <span className="text-slate-300 font-sans">
                            {eventData.simple_view.who.account_type || "Standard Account"}
                          </span>
                        </div>
                        {eventData.simple_view.who.domain && (
                          <div>
                            <span className="text-slate-500 font-sans">Domain Context:</span>{" "}
                            <span className="text-slate-300">{eventData.simple_view.who.domain}</span>
                          </div>
                        )}
                        {eventData.simple_view.who.user_sid && (
                          <div>
                            <span className="text-slate-500 font-sans">Security SID:</span>{" "}
                            <span className="text-slate-400 text-[10px]">{eventData.simple_view.who.user_sid}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 3. Where did it happen? */}
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2.5">
                      <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                        <MapPin size={16} />
                        <h3>3. Where did it happen?</h3>
                      </div>
                      <p className="text-slate-300 leading-relaxed">
                        {eventData.simple_view.where.explanation}
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-slate-800/60 font-mono text-[11px]">
                        <div>
                          <span className="text-slate-500 font-sans">Computer:</span>{" "}
                          <span className="text-slate-200">{eventData.simple_view.where.monitored_device}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-sans">Log Channel:</span>{" "}
                          <span className="text-slate-300">{eventData.simple_view.where.channel || "Security"}</span>
                        </div>
                        {eventData.simple_view.where.source_ip && (
                          <div>
                            <span className="text-slate-500 font-sans">Source IP:</span>{" "}
                            <span className="text-cyan-400">{eventData.simple_view.where.source_ip}</span>
                          </div>
                        )}
                        {eventData.simple_view.where.process_path && (
                          <div className="sm:col-span-2 truncate">
                            <span className="text-slate-500 font-sans">Process Path:</span>{" "}
                            <span className="text-slate-300" title={eventData.simple_view.where.process_path}>
                              {eventData.simple_view.where.process_path}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 4. When did it happen? */}
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2">
                      <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                        <Clock size={16} />
                        <h3>4. When did it happen?</h3>
                      </div>
                      <div className="flex items-baseline gap-2">
                        <span className="text-slate-100 font-mono text-sm font-semibold">
                          {eventData.simple_view.when.timestamp_formatted}
                        </span>
                        <span className="text-slate-400 font-mono text-xs">
                          ({eventData.simple_view.when.relative_time})
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500">
                        Event timestamp recorded in UTC by the Windows endpoint collector.
                      </p>
                    </div>

                    {/* 5. Why does it matter? */}
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2">
                      <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                        <ShieldAlert size={16} />
                        <h3>5. Why does it matter?</h3>
                      </div>
                      <p className="text-slate-300 leading-relaxed text-xs">
                        {eventData.simple_view.why_it_matters}
                      </p>
                    </div>

                    {/* When is this normal? */}
                    {eventData.simple_view.normal_when && eventData.simple_view.normal_when.length > 0 && (
                      <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2.5">
                        <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                          <CheckCircle2 size={16} />
                          <h3>When is this normal?</h3>
                        </div>
                        <ul className="space-y-1.5">
                          {eventData.simple_view.normal_when.map((item, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-slate-300">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 flex-shrink-0" />
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* When is this suspicious? */}
                    {eventData.simple_view.suspicious_when && eventData.simple_view.suspicious_when.length > 0 && (
                      <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2.5">
                        <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
                          <AlertTriangle size={16} />
                          <h3>When is this suspicious?</h3>
                        </div>
                        <ul className="space-y-1.5">
                          {eventData.simple_view.suspicious_when.map((item, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-slate-300">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 flex-shrink-0" />
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* 6. What should I do? */}
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2.5">
                      <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                        <CheckCircle2 size={16} />
                        <h3>6. What should I do?</h3>
                      </div>
                      <ul className="space-y-2">
                        {eventData.simple_view.what_should_i_do.map((rec, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-slate-300">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 flex-shrink-0" />
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                  </div>
                )}

                {/* VIEW MODE 2: ANALYST VIEW (Forensic Evidence & MITRE) */}
                {viewMode === "analyst" && (
                  <div className="space-y-5 text-xs font-mono">
                    
                    {/* MITRE ATT&CK Card or Strict Forensic Unmapped Notice */}
                    {eventData.analyst_view.mitre_attack ? (
                      <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 space-y-2.5 font-sans">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] uppercase font-bold text-cyan-300 tracking-wider">
                            MITRE ATT&CK® Technique (Detection Correlated)
                          </span>
                          <a
                            href={eventData.analyst_view.mitre_attack.url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 underline font-mono"
                          >
                            {eventData.analyst_view.mitre_attack.technique_id} <ExternalLink size={12} />
                          </a>
                        </div>
                        <p className="text-sm font-bold text-slate-100">
                          {eventData.analyst_view.mitre_attack.technique_name}
                        </p>
                        <p className="text-xs text-slate-400">
                          Tactics: {eventData.analyst_view.mitre_attack.tactic}
                        </p>
                        {eventData.analyst_view.mitre_attack.mapping_reason && (
                          <div className="text-[11px] text-slate-300 pt-2 border-t border-cyan-500/20">
                            <span className="text-cyan-400 font-semibold">Mapping Reason:</span>{" "}
                            {eventData.analyst_view.mitre_attack.mapping_reason}
                          </div>
                        )}
                        {eventData.analyst_view.mitre_attack.supporting_evidence && (
                          <div className="text-[11px] text-slate-400">
                            <span className="text-cyan-400 font-semibold">Supporting Evidence:</span>{" "}
                            {eventData.analyst_view.mitre_attack.supporting_evidence}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 font-sans space-y-1.5">
                        <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                          <ShieldCheck size={14} className="text-slate-500" />
                          <span>No verified MITRE ATT&CK mapping available for this event.</span>
                        </div>
                        <p className="text-[11px] text-slate-500 leading-relaxed">
                          CyberGuard AI adheres to strict forensic standards: adversary technique classifications are applied only when detection engine rules identify suspicious or anomalous indicators, not based on Event ID alone.
                        </p>
                      </div>
                    )}

                    {/* Technical Properties Table (Hides Missing/Null Fields) */}
                    <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
                      <div className="p-3 bg-slate-950/80 border-b border-slate-800 font-sans font-bold text-slate-200 text-xs flex items-center justify-between">
                        <span>Technical Evidence & Forensic Properties</span>
                        <span className="text-[11px] text-slate-500 font-normal">
                          {Object.keys(eventData.analyst_view.technical_properties).length} attributes
                        </span>
                      </div>
                      <div className="divide-y divide-slate-800/70">
                        {Object.entries(eventData.analyst_view.technical_properties).map(([key, val]) => (
                          <div key={key} className="grid grid-cols-3 p-2.5 hover:bg-slate-900/40 transition-colors">
                            <span className="text-slate-400 font-medium text-[11px]">{key}</span>
                            <span className="col-span-2 text-slate-200 text-[11px] break-all select-all">
                              {String(val)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Detection Rule Link */}
                    {eventData.analyst_view.detection_rule && (
                      <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center justify-between font-sans">
                        <span>Triggered Detection Rule:</span>
                        <span className="font-mono font-bold">{eventData.analyst_view.detection_rule}</span>
                      </div>
                    )}

                    {/* Expandable Original Raw Payload */}
                    <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden font-sans">
                      <button
                        type="button"
                        onClick={() => setIsRawExpanded(!isRawExpanded)}
                        className="w-full p-3 bg-slate-950/80 flex items-center justify-between text-left hover:bg-slate-900/50 transition-colors"
                      >
                        <span className="font-bold text-slate-200 text-xs flex items-center gap-2">
                          {isRawExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                          View Original Windows Event (Raw Payload)
                        </span>
                        <span className="text-[11px] text-slate-500 font-mono">
                          {Object.keys(eventData.analyst_view.raw_payload || {}).length} fields
                        </span>
                      </button>

                      {isRawExpanded && (
                        <div className="p-4 border-t border-slate-800 bg-slate-950/90 relative">
                          <button
                            type="button"
                            onClick={handleCopyPayload}
                            className="absolute top-4 right-4 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-sans flex items-center gap-1.5 transition-colors border border-slate-700"
                          >
                            {copied ? (
                              <>
                                <Check size={12} className="text-emerald-400" /> Copied
                              </>
                            ) : (
                              <>
                                <Copy size={12} /> Copy Payload
                              </>
                            )}
                          </button>
                          <pre className="text-[11px] font-mono text-cyan-300 overflow-x-auto p-2 bg-slate-950 rounded border border-slate-900 leading-relaxed max-h-96">
                            {JSON.stringify(eventData.analyst_view.raw_payload, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>

                  </div>
                )}
              </>
            )}
          </div>

          {/* Fixed Footer with Close Action */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs text-slate-400 flex-shrink-0">
            <span className="text-[11px] text-slate-500 font-mono">
              CyberGuard Event Engine • Knowledge Base v1.0
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={onClose}
              className="border-slate-800 text-slate-300 hover:bg-slate-800 text-xs px-4"
            >
              Close
            </Button>
          </div>

        </div>
      </div>
    </div>
  );
}

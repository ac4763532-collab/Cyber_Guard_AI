/**
 * CyberGuard AI — Devices (Sources) Page
 * ============================================================================
 * 
 * Manages the enrollment and health of data collectors.
 * 
 * Features:
 *   - Lists all connected devices (Windows, Linux, macOS).
 *   - Shows live connection status (Heartbeat check).
 *   - "Connect Device" modal:
 *       1. Choose OS.
 *       2. Backend creates a Source and generates an Enrollment Token.
 *       3. Displays the exact installation command for the user to copy.
 */

import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Plus, Monitor, Server, Apple, CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { formatRelativeTime } from "@/lib/utils";

import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";
import { DeviceConnectionWizard } from "@/components/devices/DeviceConnectionWizard";


// ============================================================================
// LOCAL TYPES (Mirroring backend schema)
// ============================================================================

interface DeviceItem {
  id: string;
  name: string;
  type: string;
  os_version: string | null;
  agent_version: string | null;
  hostname: string | null;
  ip_address: string | null;
  status: string;
  last_scan: string | null;
  last_heartbeat: string | null;
  threat_count: number;
  collector_connected: boolean;
  source_key: string;
  created_at: string;
}

type OS = "windows" | "linux" | "macos";


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Devices() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [isModalOpen, setIsModalOpen] = useState(searchParams.get("connect") === "true");

  useEffect(() => {
    if (searchParams.get("connect") === "true") {
      setIsModalOpen(true);
    }
  }, [searchParams]);

  // ── Fetch Devices ─────────────────────────────────────────────────────
  const { data, isLoading } = useQuery<DeviceItem[] | { items: DeviceItem[]; total?: number }>({
    queryKey: ["devices"],
    queryFn: async () => {
      const { data } = await api.get<DeviceItem[] | { items: DeviceItem[]; total?: number }>("/devices");
      return data;
    },
    refetchInterval: 8000, 
  });

  const deviceList: DeviceItem[] = Array.isArray(data)
    ? data
    : (data?.items ?? []);

  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Devices
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Connect your servers, laptops, and firewalls to start monitoring.
          </p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} leftIcon={<Plus size={16} />}>
          Connect Device
        </Button>
      </div>

      {/* ── Device Table ───────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading devices..." /></CardContent></Card>
      ) : deviceList.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center p-12 text-center">
            <Monitor size={48} className="text-slate-300 dark:text-slate-600 mb-4" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">No devices connected</h3>
            <p className="mt-1 text-sm text-slate-500 max-w-sm">
              Install the CyberGuard collector on your machine to begin streaming logs and detecting threats.
            </p>
            <Button className="mt-6" onClick={() => setIsModalOpen(true)}>
              Connect your first device
            </Button>
          </CardContent>
        </Card>
      ) : (
        <TableWrapper>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden md:table-cell">Last Seen</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {deviceList.map((device) => (
                <TableRow
                  key={device.id}
                  interactive
                  onClick={() => navigate(`/personal/devices/${device.id}`)}
                  className="cursor-pointer"
                >
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="font-medium text-slate-900 dark:text-slate-100">
                        {device.name}
                      </span>
                      <span className="text-xs text-slate-500 font-mono">
                        {device.hostname || device.source_key}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 text-sm capitalize text-slate-600 dark:text-slate-400">
                      {device.type === "windows" && <Monitor size={16} />}
                      {device.type === "linux" && <Server size={16} />}
                      {device.type === "macos" && <Apple size={16} />}
                      {device.type}
                    </div>
                  </TableCell>
                  <TableCell>
                    {device.collector_connected ? (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-green-600 dark:text-green-400">
                        <CheckCircle2 size={16} /> Online
                      </div>
                    ) : device.status === "pending_enrollment" || device.status === "pending" ? (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-amber-600 dark:text-amber-400">
                        <AlertCircle size={16} /> Waiting for install...
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-slate-500 dark:text-slate-400">
                        <XCircle size={16} /> Offline
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-slate-500">
                    {device.last_heartbeat ? formatRelativeTime(device.last_heartbeat) : "Never"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/personal/devices/${device.id}`);
                      }}
                    >
                      View Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableWrapper>
      )}

      <DeviceConnectionWizard
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setSearchParams({});
        }}
      />
    </div>
  );
}

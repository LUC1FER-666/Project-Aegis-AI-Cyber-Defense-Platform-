"use client";

import { useState, useEffect } from "react";
import {
  AlertTriangle, Shield, Server, Activity,
  TrendingUp, Clock, CheckCircle, XCircle,
  ArrowUpRight, Eye, Zap
} from "lucide-react";
import { clsx } from "clsx";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Severity = "critical" | "high" | "medium" | "low";

interface MetricCard {
  label: string;
  value: string | number;
  change?: string;
  trend?: "up" | "down" | "neutral";
  icon: React.ComponentType<{ className?: string }>;
  color: string;
}

interface RecentIncident {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  asset: string;
  time: string;
  mitre: string;
}

// ---------------------------------------------------------------------------
// Mock data — replaced by real API calls in later milestones
// ---------------------------------------------------------------------------
const mockMetrics: MetricCard[] = [
  {
    label: "Open Incidents",
    value: 3,
    change: "+1 today",
    trend: "up",
    icon: AlertTriangle,
    color: "text-red-400",
  },
  {
    label: "Assets Monitored",
    value: 0,
    change: "Run first scan",
    trend: "neutral",
    icon: Server,
    color: "text-cyan-400",
  },
  {
    label: "Events (24h)",
    value: 0,
    change: "Start telemetry",
    trend: "neutral",
    icon: Activity,
    color: "text-purple-400",
  },
  {
    label: "Detections (24h)",
    value: 0,
    change: "Engine starting",
    trend: "neutral",
    icon: Eye,
    color: "text-yellow-400",
  },
];

const mockIncidents: RecentIncident[] = [
  {
    id: "INC-001",
    title: "Suspicious PowerShell execution detected",
    severity: "high",
    status: "investigating",
    asset: "WORKSTATION-14",
    time: "12 min ago",
    mitre: "T1059.001",
  },
  {
    id: "INC-002",
    title: "Brute force login attempt — SSH",
    severity: "medium",
    status: "open",
    asset: "web-server-01",
    time: "34 min ago",
    mitre: "T1110",
  },
  {
    id: "INC-003",
    title: "Unusual outbound DNS to known C2",
    severity: "critical",
    status: "investigating",
    asset: "DESKTOP-7F2A",
    time: "1h ago",
    mitre: "T1071.004",
  },
];

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx("px-2 py-0.5 rounded text-xs font-medium", `severity-${severity}`)}>
      {severity.toUpperCase()}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    open: "bg-yellow-500/20 text-yellow-400",
    investigating: "bg-blue-500/20 text-blue-400",
    contained: "bg-purple-500/20 text-purple-400",
    resolved: "bg-green-500/20 text-green-400",
  };
  return (
    <span className={clsx("px-2 py-0.5 rounded text-xs font-medium", colors[status] || "bg-gray-500/20 text-gray-400")}>
      {status}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SOCDashboard() {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">SOC Dashboard</h1>
          <p className="text-gray-400 text-sm mt-1">
            Security Operations Center — Real-time View
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-gray-800 rounded-lg px-3 py-2">
            <Clock className="w-4 h-4 text-gray-400" />
            <span className="text-sm text-gray-300 font-mono">
              {currentTime.toUTCString().slice(17, 25)} UTC
            </span>
          </div>
          <div className="flex items-center gap-2 bg-green-500/10 border border-green-500/20 rounded-lg px-3 py-2">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-sm text-green-400">Systems Nominal</span>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-4 gap-4">
        {mockMetrics.map((metric) => (
          <div
            key={metric.label}
            className="bg-gray-900 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-colors"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-gray-400 text-sm">{metric.label}</span>
              <metric.icon className={clsx("w-5 h-5", metric.color)} />
            </div>
            <div className="text-3xl font-bold text-white mb-1">{metric.value}</div>
            <div className={clsx(
              "text-xs flex items-center gap-1",
              metric.trend === "up" ? "text-red-400" :
              metric.trend === "down" ? "text-green-400" : "text-gray-500"
            )}>
              {metric.trend === "up" && <TrendingUp className="w-3 h-3" />}
              {metric.change}
            </div>
          </div>
        ))}
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-3 gap-6">

        {/* Recent Incidents — 2 cols */}
        <div className="col-span-2 bg-gray-900 border border-gray-800 rounded-xl">
          <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <h2 className="font-semibold text-white">Active Incidents</h2>
              <span className="ml-1 bg-red-500/20 text-red-400 text-xs px-2 py-0.5 rounded-full">
                {mockIncidents.length}
              </span>
            </div>
            <a href="/incidents" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
              View all <ArrowUpRight className="w-3 h-3" />
            </a>
          </div>
          <div className="divide-y divide-gray-800">
            {mockIncidents.map((incident) => (
              <div
                key={incident.id}
                className="px-5 py-4 hover:bg-gray-800/50 transition-colors cursor-pointer"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="text-xs text-gray-500 font-mono">{incident.id}</span>
                      <SeverityBadge severity={incident.severity} />
                      <StatusBadge status={incident.status} />
                    </div>
                    <p className="text-sm text-gray-200 font-medium truncate">{incident.title}</p>
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="text-xs text-gray-500 flex items-center gap-1">
                        <Server className="w-3 h-3" /> {incident.asset}
                      </span>
                      <span className="text-xs text-gray-600">•</span>
                      <span className="text-xs text-gray-500 font-mono bg-gray-800 px-1.5 py-0.5 rounded">
                        {incident.mitre}
                      </span>
                    </div>
                  </div>
                  <div className="text-xs text-gray-500 whitespace-nowrap">{incident.time}</div>
                </div>
              </div>
            ))}
          </div>
          {mockIncidents.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-gray-600">
              <CheckCircle className="w-8 h-8 mb-2" />
              <p className="text-sm">No active incidents</p>
            </div>
          )}
        </div>

        {/* Platform Status — 1 col */}
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h2 className="font-semibold text-white mb-4 flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Service Status
            </h2>
            <div className="space-y-3">
              {[
                { name: "Gateway",            port: "8000", status: "online" },
                { name: "Asset Discovery",    port: "8001", status: "starting" },
                { name: "Telemetry",          port: "8002", status: "starting" },
                { name: "Detection Engine",   port: "8004", status: "offline" },
                { name: "Agent Orchestrator", port: "8005", status: "offline" },
                { name: "Knowledge Graph",    port: "8006", status: "offline" },
              ].map((svc) => (
                <div key={svc.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={clsx(
                      "w-2 h-2 rounded-full",
                      svc.status === "online" ? "bg-green-400" :
                      svc.status === "starting" ? "bg-yellow-400 animate-pulse" :
                      "bg-gray-600"
                    )} />
                    <span className="text-sm text-gray-300">{svc.name}</span>
                  </div>
                  <span className="text-xs text-gray-500 font-mono">:{svc.port}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h2 className="font-semibold text-white mb-4">Quick Actions</h2>
            <div className="space-y-2">
              <a
                href="/assets"
                className="flex items-center gap-2 w-full bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 text-cyan-400 text-sm px-3 py-2.5 rounded-lg transition-colors"
              >
                <Server className="w-4 h-4" />
                Run Asset Scan
              </a>
              <a
                href="/incidents"
                className="flex items-center gap-2 w-full bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-3 py-2.5 rounded-lg transition-colors"
              >
                <AlertTriangle className="w-4 h-4" />
                View Incidents
              </a>
              <a
                href="/graph"
                className="flex items-center gap-2 w-full bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-3 py-2.5 rounded-lg transition-colors"
              >
                <Activity className="w-4 h-4" />
                Knowledge Graph
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

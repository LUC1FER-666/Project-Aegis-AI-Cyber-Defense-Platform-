"use client";

import { useState } from "react";
import {
  Server, Plus, Search, RefreshCw, Shield,
  Wifi, HardDrive, Globe, AlertTriangle
} from "lucide-react";
import { clsx } from "clsx";

type AssetType = "endpoint" | "server" | "network_device" | "cloud_vm" | "unknown";
type Criticality = 1 | 2 | 3 | 4;

interface Asset {
  id: string;
  hostname: string | null;
  ip_address: string;
  asset_type: AssetType;
  os_name: string | null;
  criticality: Criticality;
  risk_score: number;
  is_active: boolean;
  last_seen: string;
  open_ports: number[];
}

const ASSET_TYPE_ICONS: Record<AssetType, React.ComponentType<{ className?: string }>> = {
  endpoint: HardDrive,
  server: Server,
  network_device: Wifi,
  cloud_vm: Globe,
  unknown: Shield,
};

const CRITICALITY_LABELS: Record<Criticality, { label: string; color: string }> = {
  1: { label: "Critical", color: "text-red-400 bg-red-500/10 border-red-500/20" },
  2: { label: "High",     color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
  3: { label: "Medium",   color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
  4: { label: "Low",      color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
};

// Sample assets — replaced by API when asset-discovery is running
const SAMPLE_ASSETS: Asset[] = [];

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? "bg-red-500" : score >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div className={clsx("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-400">{score.toFixed(0)}</span>
    </div>
  );
}

export default function AssetsPage() {
  const [scanTarget, setScanTarget] = useState("192.168.1.0/24");
  const [scanning, setScanning] = useState(false);
  const [search, setSearch] = useState("");
  const [scanResult, setScanResult] = useState<string | null>(null);

  const triggerScan = async () => {
    setScanning(true);
    setScanResult(null);
    try {
      const token = localStorage.getItem("access_token") || "";
      const resp = await fetch("http://localhost:8001/api/v1/scans", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ scan_type: "network", target: scanTarget }),
      });
      if (resp.ok) {
        const data = await resp.json();
        setScanResult(`Scan started — Job ID: ${data.id}`);
      } else {
        setScanResult("Scan failed — check asset-discovery service logs");
      }
    } catch {
      setScanResult("Cannot reach asset-discovery service (start it first)");
    } finally {
      setScanning(false);
    }
  };

  const filtered = SAMPLE_ASSETS.filter(
    (a) =>
      !search ||
      a.ip_address.includes(search) ||
      (a.hostname || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Asset Inventory</h1>
          <p className="text-gray-400 text-sm mt-1">
            All discovered assets across your environment
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-400">
            {SAMPLE_ASSETS.length} assets
          </span>
        </div>
      </div>

      {/* Scan trigger */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Search className="w-4 h-4 text-cyan-400" />
          <h2 className="font-semibold text-white">Network Discovery Scan</h2>
        </div>
        <p className="text-sm text-gray-400 mb-4">
          Scan a network range to discover assets. Only scan networks you own or have permission to test.
        </p>
        <div className="flex gap-3">
          <input
            type="text"
            value={scanTarget}
            onChange={(e) => setScanTarget(e.target.value)}
            placeholder="e.g. 192.168.1.0/24 or 10.0.0.1"
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={triggerScan}
            disabled={scanning}
            className="flex items-center gap-2 bg-cyan-500 hover:bg-cyan-400 disabled:bg-cyan-500/50 text-black font-semibold px-5 py-2.5 rounded-lg text-sm transition-colors"
          >
            {scanning ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Plus className="w-4 h-4" />
            )}
            {scanning ? "Scanning..." : "Start Scan"}
          </button>
        </div>
        {scanResult && (
          <div className={clsx(
            "mt-3 text-sm px-3 py-2 rounded-lg",
            scanResult.includes("started")
              ? "bg-green-500/10 text-green-400 border border-green-500/20"
              : "bg-red-500/10 text-red-400 border border-red-500/20"
          )}>
            {scanResult}
          </div>
        )}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by IP or hostname..."
          className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
        />
      </div>

      {/* Asset Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Asset</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Type</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">OS</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Criticality</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Risk</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Ports</th>
              <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {filtered.map((asset) => {
              const Icon = ASSET_TYPE_ICONS[asset.asset_type] || Shield;
              const crit = CRITICALITY_LABELS[asset.criticality];
              return (
                <tr key={asset.id} className="hover:bg-gray-800/50 cursor-pointer transition-colors">
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-gray-800 flex items-center justify-center">
                        <Icon className="w-4 h-4 text-gray-400" />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-white">
                          {asset.hostname || asset.ip_address}
                        </div>
                        {asset.hostname && (
                          <div className="text-xs text-gray-500 font-mono">{asset.ip_address}</div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3.5 text-sm text-gray-400">{asset.asset_type}</td>
                  <td className="px-5 py-3.5 text-sm text-gray-400">{asset.os_name || "—"}</td>
                  <td className="px-5 py-3.5">
                    <span className={clsx("text-xs px-2 py-0.5 rounded border", crit.color)}>
                      {crit.label}
                    </span>
                  </td>
                  <td className="px-5 py-3.5">
                    <RiskBar score={asset.risk_score} />
                  </td>
                  <td className="px-5 py-3.5 text-sm text-gray-400">
                    {asset.open_ports.slice(0, 4).join(", ")}
                    {asset.open_ports.length > 4 && ` +${asset.open_ports.length - 4}`}
                  </td>
                  <td className="px-5 py-3.5 text-xs text-gray-500">{asset.last_seen}</td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-gray-600">
            <Server className="w-10 h-10 mb-3 opacity-40" />
            <p className="text-sm font-medium text-gray-500">No assets discovered yet</p>
            <p className="text-xs mt-1">Run a network scan above to populate the inventory</p>
          </div>
        )}
      </div>
    </div>
  );
}

"use client";

import { useEffect, useRef, useState, useCallback } from "react";

const AGENT_URL = process.env.NEXT_PUBLIC_AGENT_URL ?? "http://localhost:8005";
const DEFENSE_URL = "http://localhost:8006";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Prediction {
  id: string;
  prediction_id: string;
  threat_type: string;
  confidence: number;
  affected_assets: string[];
  evidence_summary: string;
  predicted_attack_vector: string;
  recommended_actions: string[];
  status: string;
  expires_at: string;
  created_at: string;
}

interface Narrative {
  id: string;
  source_type: string;
  source_id: string;
  headline: string;
  severity_assessment: string;
  attack_timeline: string[];
  likely_objective: string;
  immediate_actions: string[];
  technical_indicators: string[];
  confidence: number;
  created_at: string;
}

interface Notification {
  id?: string;
  notification_type: string;
  title: string;
  body: string;
  severity: string;
  read: boolean;
  asset_ids?: string[];
  created_at: string;
}

interface PreemptiveAction {
  id: string;
  action_type: string;
  target: string;
  status: string;
  confidence_trigger: number;
  executed_at: string;
  result_data?: Record<string, unknown>;
}

interface DefenseStats {
  active_predictions: number;
  notifications_unread: number;
  narratives_generated: number;
  preemptive_actions_taken: number;
  agent_status: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T | null> {
  try {
    const res = await fetch(url, { ...options, cache: "no-store" });
    if (!res.ok) return null;
    return await res.json() as T;
  } catch {
    return null;
  }
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

function timeUntil(dateStr: string): string {
  const diff = new Date(dateStr).getTime() - Date.now();
  if (diff <= 0) return "expired";
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m`;
}

const SEV_COLOR: Record<string, string> = {
  critical: "#ff4444", high: "#ff8800", medium: "#f59e0b", low: "#00ff88",
};

const THREAT_ICONS: Record<string, string> = {
  brute_force_imminent: "🔑",
  dns_tunnel_imminent: "🌐",
  c2_beacon_imminent: "📡",
  account_compromise: "👤",
  lateral_spread_imminent: "↔",
};

// ── Notification Feed Item ────────────────────────────────────────────────────

function NotifItem({ notif, isNew }: { notif: Notification; isNew: boolean }) {
  const color = SEV_COLOR[notif.severity] ?? "#64748b";
  return (
    <div
      className={`rounded-lg border p-3 transition-all duration-500 ${isNew ? "animate-pulse" : ""}`}
      style={{
        borderColor: color + "40",
        background: color + "08",
        boxShadow: isNew ? `0 0 12px ${color}33` : "none",
      }}
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <p className="text-xs font-medium text-[#e2e8f0] leading-tight">{notif.title}</p>
        <span className="text-[10px] text-[#64748b] whitespace-nowrap flex-shrink-0">{timeAgo(notif.created_at)}</span>
      </div>
      <p className="text-[11px] text-[#64748b] leading-relaxed">{notif.body}</p>
      <div className="mt-1.5 flex items-center gap-2">
        <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: color + "20", color }}>
          {notif.notification_type.replace(/_/g, " ")}
        </span>
        {notif.asset_ids && notif.asset_ids.length > 0 && (
          <span className="text-[10px] text-[#64748b] font-mono">{notif.asset_ids[0]}</span>
        )}
      </div>
    </div>
  );
}

// ── Prediction Card ───────────────────────────────────────────────────────────

function PredictionCard({ pred }: { pred: Prediction }) {
  const color = pred.confidence >= 0.85 ? "#ff4444" : pred.confidence >= 0.75 ? "#ff8800" : "#f59e0b";
  const icon = THREAT_ICONS[pred.threat_type] ?? "⚠";
  const ttl = timeUntil(pred.expires_at);

  return (
    <div className="bg-[#0d1528] border border-[#1a2744] rounded-xl p-4 hover:border-[#ff8800]/30 transition-all"
      style={{ boxShadow: pred.confidence >= 0.85 ? "0 0 12px #ff444411" : "none" }}>
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xl">{icon}</span>
          <div>
            <p className="text-xs font-semibold text-[#e2e8f0]">{pred.threat_type.replace(/_/g, " ")}</p>
            <p className="text-[10px] text-[#64748b]">Expires in {ttl}</p>
          </div>
        </div>
        <span className="text-sm font-bold" style={{ color }}>{Math.round(pred.confidence * 100)}%</span>
      </div>

      {/* Confidence bar */}
      <div className="h-1.5 bg-[#1a2744] rounded-full overflow-hidden mb-3">
        <div className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pred.confidence * 100}%`, background: color }} />
      </div>

      <p className="text-[11px] text-[#64748b] mb-3 leading-relaxed">{pred.evidence_summary}</p>

      {pred.affected_assets?.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {pred.affected_assets.slice(0, 3).map(a => (
            <span key={a} className="text-[10px] bg-[#1a2744] text-[#64748b] px-2 py-0.5 rounded font-mono">{a}</span>
          ))}
        </div>
      )}

      {pred.recommended_actions?.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] text-[#64748b] uppercase tracking-widest">Recommended Actions</p>
          {pred.recommended_actions.slice(0, 3).map((a, i) => (
            <div key={i} className="flex items-center gap-1.5 text-[11px] text-[#e2e8f0]">
              <span style={{ color }}>›</span> {a.replace(/_/g, " ")}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Narrative Card ────────────────────────────────────────────────────────────

function NarrativeCard({ narrative }: { narrative: Narrative }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-[#0d1528] border border-[#1a2744] rounded-xl p-4">
      <div className="flex items-start justify-between gap-2 mb-2">
        <p className="text-sm font-semibold text-[#e2e8f0] leading-tight">{narrative.headline}</p>
        <span className="text-[10px] text-[#64748b] flex-shrink-0">{timeAgo(narrative.created_at)}</span>
      </div>
      <p className="text-[11px] text-[#ff8800] mb-2">{narrative.severity_assessment}</p>
      <p className="text-[11px] text-[#64748b] mb-3">{narrative.likely_objective}</p>

      <button onClick={() => setExpanded(e => !e)}
        className="text-[10px] text-[#00d4ff] hover:text-[#00d4ff]/80 transition-colors">
        {expanded ? "▲ Hide details" : "▼ Show full briefing"}
      </button>

      {expanded && (
        <div className="mt-3 space-y-3">
          {narrative.attack_timeline?.length > 0 && (
            <div>
              <p className="text-[10px] text-[#64748b] uppercase tracking-widest mb-1.5">Attack Timeline</p>
              <div className="space-y-1">
                {narrative.attack_timeline.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 text-[11px] text-[#e2e8f0]">
                    <span className="text-[#00d4ff] flex-shrink-0 font-mono">{i + 1}.</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {narrative.immediate_actions?.length > 0 && (
            <div>
              <p className="text-[10px] text-[#64748b] uppercase tracking-widest mb-1.5">Immediate Actions</p>
              {narrative.immediate_actions.map((a, i) => (
                <div key={i} className="flex items-center gap-2 text-[11px] text-[#00ff88]">
                  <span>✓</span> <span>{a}</span>
                </div>
              ))}
            </div>
          )}

          {narrative.technical_indicators?.length > 0 && (
            <div>
              <p className="text-[10px] text-[#64748b] uppercase tracking-widest mb-1.5">Technical Indicators</p>
              {narrative.technical_indicators.map((ioc, i) => (
                <div key={i} className="text-[11px] font-mono text-[#64748b]">• {ioc}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DefensePage() {
  const [stats, setStats] = useState<DefenseStats | null>(null);
  const [predictions, setPredictions] = useState<Prediction[]>([]);
  const [narratives, setNarratives] = useState<Narrative[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [newNotifIds, setNewNotifIds] = useState<Set<string>>(new Set());
  const [actions, setActions] = useState<PreemptiveAction[]>([]);
  const [running, setRunning] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [sseStatus, setSseStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const esRef = useRef<EventSource | null>(null);
  const notifEndRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    const [s, p, n] = await Promise.all([
      apiFetch<DefenseStats>(`${DEFENSE_URL}/stats`),
      apiFetch<Prediction[]>(`${DEFENSE_URL}/api/v1/predictions?status=active`),
      apiFetch<Narrative[]>(`${DEFENSE_URL}/api/v1/narratives`),
    ]);
    if (s) setStats(s);
    if (p) setPredictions(p);
    if (n) setNarratives(n);
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10_000);
    return () => clearInterval(t);
  }, [refresh]);

  // SSE connection
  useEffect(() => {
    const connect = () => {
      const es = new EventSource(`${DEFENSE_URL}/api/v1/notifications/stream`);
      esRef.current = es;

      es.addEventListener("connected", () => setSseStatus("connected"));
      es.addEventListener("heartbeat", () => {});

      es.addEventListener("notification", (e) => {
        try {
          const notif: Notification = JSON.parse(e.data);
          const tempId = `sse-${Date.now()}`;
          const withId = { ...notif, id: notif.id ?? tempId };
          setNotifications(prev => [withId, ...prev].slice(0, 50));
          setNewNotifIds(prev => new Set([...prev, withId.id ?? tempId]));
          setTimeout(() => {
            setNewNotifIds(prev => {
              const n = new Set(prev);
              n.delete(withId.id ?? tempId);
              return n;
            });
          }, 3000);
          notifEndRef.current?.scrollIntoView({ behavior: "smooth" });
        } catch {}
      });

      es.onerror = () => {
        setSseStatus("disconnected");
        es.close();
        setTimeout(connect, 5000);
      };
    };

    connect();
    return () => {
      esRef.current?.close();
    };
  }, []);

  // Load existing notifications on mount
  useEffect(() => {
    apiFetch<Notification[]>(`${DEFENSE_URL}/api/v1/notifications?read=false`).then(data => {
      if (data) setNotifications(data);
    });
  }, []);

  const runAgent = async () => {
    setRunning(true);
    await apiFetch(`${DEFENSE_URL}/api/v1/agent/run`, { method: "POST" });
    setRunning(false);
    refresh();
  };

  const generateBriefing = async () => {
    setGenerating(true);
    await apiFetch(`${DEFENSE_URL}/api/v1/narratives/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source_type: "manual", source_id: "dashboard", context: {} }),
    });
    setGenerating(false);
    refresh();
  };

  const markAllRead = async () => {
    await apiFetch(`${DEFENSE_URL}/api/v1/notifications/read-all`, { method: "PATCH" });
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  return (
    <div className="p-6 space-y-5 min-h-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-[#e2e8f0]">Defense Command Center</h1>
          <p className="text-xs text-[#64748b] mt-0.5">Proactive threat defense · predictive analysis · real-time response</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className={`w-1.5 h-1.5 rounded-full ${sseStatus === "connected" ? "bg-[#00ff88] animate-pulse" : sseStatus === "connecting" ? "bg-[#f59e0b] animate-pulse" : "bg-[#ff4444]"}`} />
            <span className="text-[10px] text-[#64748b]">SSE {sseStatus}</span>
          </div>
          <button onClick={generateBriefing} disabled={generating}
            className="px-3 py-2 text-xs bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/30 rounded-lg hover:bg-[#00d4ff]/20 transition-colors disabled:opacity-50">
            {generating ? "Generating..." : "📋 Generate Briefing"}
          </button>
          <button onClick={runAgent} disabled={running}
            className="px-3 py-2 text-xs bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/30 rounded-lg hover:bg-[#00ff88]/20 transition-colors disabled:opacity-50">
            {running ? "Running..." : "▶ Run Defense Agent"}
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          {[
            { label: "Active Predictions", value: stats.active_predictions, color: "#ff8800" },
            { label: "Unread Notifications", value: stats.notifications_unread, color: "#ff4444" },
            { label: "Narratives Generated", value: stats.narratives_generated, color: "#00d4ff" },
            { label: "Preemptive Actions", value: stats.preemptive_actions_taken, color: "#00ff88" },
            { label: "Agent Status", value: stats.agent_status, color: "#f59e0b" },
          ].map(m => (
            <div key={m.label} className="bg-[#0d1528] border border-[#1a2744] rounded-xl px-4 py-3">
              <div className="text-[10px] text-[#64748b] uppercase tracking-widest mb-1">{m.label}</div>
              <div className="text-xl font-bold capitalize" style={{ color: m.color }}>{m.value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-3 gap-5">
        {/* Notification Feed (SSE) */}
        <div className="flex flex-col bg-[#0d1528] border border-[#1a2744] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1a2744] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h3 className="text-xs text-[#64748b] uppercase tracking-widest">Live Notifications</h3>
              {notifications.filter(n => !n.read).length > 0 && (
                <span className="text-[10px] bg-[#ff4444] text-white px-1.5 py-0.5 rounded-full font-bold">
                  {notifications.filter(n => !n.read).length}
                </span>
              )}
            </div>
            <button onClick={markAllRead} className="text-[10px] text-[#64748b] hover:text-[#00d4ff] transition-colors">
              Mark all read
            </button>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-2 max-h-[600px]">
            {notifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-[#64748b] text-xs text-center">
                <span className="text-2xl mb-1">🔔</span>
                Waiting for notifications...
                <br />Run the defense agent to generate threats
              </div>
            ) : (
              notifications.map((n, i) => (
                <NotifItem
                  key={n.id ?? i}
                  notif={n}
                  isNew={newNotifIds.has(n.id ?? "")}
                />
              ))
            )}
            <div ref={notifEndRef} />
          </div>
        </div>

        {/* Active Predictions */}
        <div className="flex flex-col bg-[#0d1528] border border-[#1a2744] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1a2744]">
            <h3 className="text-xs text-[#64748b] uppercase tracking-widest">Active Predictions</h3>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-3 max-h-[600px]">
            {predictions.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-[#64748b] text-xs text-center">
                <span className="text-2xl mb-1">🛡</span>
                No active predictions
                <br />Run the defense agent to analyze threats
              </div>
            ) : (
              predictions.map(p => <PredictionCard key={p.id} pred={p} />)
            )}
          </div>
        </div>

        {/* Attack Narratives */}
        <div className="flex flex-col bg-[#0d1528] border border-[#1a2744] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1a2744]">
            <h3 className="text-xs text-[#64748b] uppercase tracking-widest">AI Attack Narratives</h3>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-3 max-h-[600px]">
            {narratives.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-[#64748b] text-xs text-center">
                <span className="text-2xl mb-1">📋</span>
                No narratives yet
                <br />Click "Generate Briefing" to create one
              </div>
            ) : (
              narratives.slice(0, 10).map(n => <NarrativeCard key={n.id} narrative={n} />)
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Aegis AI — Typed API Client
// All fetch calls handle errors gracefully — never throw to the UI

const DE = process.env.NEXT_PUBLIC_DETECTION_ENGINE_URL ?? "http://localhost:8004";
const AG = process.env.NEXT_PUBLIC_AGENT_URL ?? "http://localhost:8005";

// ── Types ────────────────────────────────────────────────────────────────────

export interface DetectionStats {
  total_alerts: number;
  open_alerts: number;
  suppressed_alerts: number;
  total_incidents: number;
  open_incidents: number;
  rules_loaded: number;
  ml_model_trained: boolean;
  alerts_last_hour: number;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  asset_id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  mitre_technique: string;
  confidence_score: number;
  evidence: Record<string, unknown>;
  source_log_type: string;
  status: string;
  llm_validated: boolean;
  suppressed_by_llm: boolean;
  created_at: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  status: string;
  mitre_techniques: string[];
  affected_assets: string[];
  alert_count: number;
  first_seen: string;
  last_seen: string;
  correlation_key: string;
  created_at: string;
}

export interface Rule {
  rule_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  mitre_technique: string;
  type: "sigma" | "ml";
  hit_count?: number;
  enabled?: boolean;
  description?: string;
  tags?: string[];
}

export interface AgentTask {
  id: string;
  incident_id: string;
  incident_title: string;
  severity: string;
  status: "pending_approval" | "approved" | "executing" | "completed" | "failed" | "cancelled" | "rejected";
  triage?: {
    urgency_score: number;
    attack_stage: string;
    recommended_response_tier: string;
    summary: string;
    key_indicators: string[];
  };
  selected_playbook?: string;
  playbook_steps?: Array<{ action_type: string; target: string; parameters: Record<string, unknown> }>;
  actions_results?: Array<{
    action_id: string;
    action_type: string;
    target: string;
    status: string;
    result_data: Record<string, unknown>;
    duration_ms: number;
    executed_at: string;
  }>;
  approval_notes?: string;
  approved_by?: string;
  approved_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ActionLog {
  id: string;
  task_id: string;
  action_type: string;
  target: string;
  status: string;
  result_data: Record<string, unknown>;
  duration_ms: number;
  executed_at: string;
}

export interface AgentStats {
  total_tasks: number;
  by_status: Record<string, number>;
  by_playbook: Record<string, number>;
  avg_execution_time_ms: number;
  pending_approval_count: number;
}

export interface AnalyzeResponse {
  alerts?: Alert[];
  rule_matches?: string[];
  anomaly_score?: number;
  llm_validated?: boolean;
  message?: string;
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

function qs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

// ── Detection Engine ──────────────────────────────────────────────────────────

export async function fetchStats(): Promise<DetectionStats | null> {
  return apiFetch<DetectionStats>(`${DE}/api/v1/stats`);
}

export async function fetchAlerts(params: {
  limit?: number;
  offset?: number;
  severity?: string;
  status?: string;
  search?: string;
} = {}): Promise<Alert[]> {
  const data = await apiFetch<Alert[] | { alerts: Alert[] }>(
    `${DE}/api/v1/alerts${qs(params)}`
  );
  if (!data) return [];
  return Array.isArray(data) ? data : (data as { alerts: Alert[] }).alerts ?? [];
}

export async function fetchIncidents(params: {
  limit?: number;
  status?: string;
  severity?: string;
  search?: string;
} = {}): Promise<Incident[]> {
  const data = await apiFetch<Incident[] | { incidents: Incident[] }>(
    `${DE}/api/v1/incidents${qs(params)}`
  );
  if (!data) return [];
  return Array.isArray(data) ? data : (data as { incidents: Incident[] }).incidents ?? [];
}

export async function fetchRules(): Promise<Rule[]> {
  const data = await apiFetch<Rule[] | { rules: Rule[] }>(`${DE}/api/v1/rules`);
  if (!data) return [];
  return Array.isArray(data) ? data : (data as { rules: Rule[] }).rules ?? [];
}

export async function analyzeEvent(event: Record<string, unknown>): Promise<AnalyzeResponse | null> {
  return apiFetch<AnalyzeResponse>(`${DE}/api/v1/events/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  });
}

// ── Agent Orchestrator ────────────────────────────────────────────────────────

export async function fetchTasks(params: {
  status?: string;
  severity?: string;
  page?: number;
  page_size?: number;
} = {}): Promise<{ tasks: AgentTask[]; total: number }> {
  const data = await apiFetch<{ tasks: AgentTask[]; total: number }>(
    `${AG}/api/v1/tasks${qs(params)}`
  );
  return data ?? { tasks: [], total: 0 };
}

export async function fetchTask(id: string): Promise<AgentTask | null> {
  return apiFetch<AgentTask>(`${AG}/api/v1/tasks/${id}`);
}

export async function fetchTaskActions(id: string): Promise<ActionLog[]> {
  const data = await apiFetch<ActionLog[]>(`${AG}/api/v1/tasks/${id}/actions`);
  return data ?? [];
}

export async function approveTask(id: string, notes: string, approved_by: string): Promise<AgentTask | null> {
  return apiFetch<AgentTask>(`${AG}/api/v1/tasks/${id}/approve`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes, approved_by }),
  });
}

export async function rejectTask(id: string, notes: string): Promise<AgentTask | null> {
  return apiFetch<AgentTask>(`${AG}/api/v1/tasks/${id}/reject`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes }),
  });
}

export async function fetchAgentStats(): Promise<AgentStats | null> {
  return apiFetch<AgentStats>(`${AG}/stats`);
}

export async function analyzeIncident(incident: Record<string, unknown>): Promise<AgentTask | null> {
  return apiFetch<AgentTask>(`${AG}/api/v1/incidents/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ incident }),
  });
}

// ── Utilities ─────────────────────────────────────────────────────────────────

export function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

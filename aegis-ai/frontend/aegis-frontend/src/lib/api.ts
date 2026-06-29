// Aegis AI — Typed API Client

const DETECTION_URL = process.env.NEXT_PUBLIC_DETECTION_ENGINE_URL || 'http://localhost:8004';
const AGENT_URL = process.env.NEXT_PUBLIC_AGENT_URL || 'http://localhost:8005';

// ── Types ──────────────────────────────────────────────────────────────────────

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
  id: string;
  rule_id: string;
  asset_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'open' | 'in_progress' | 'suppressed' | 'closed';
  mitre_technique: string | null;
  confidence_score: number;
  anomaly_score: number | null;
  llm_validated: boolean | null;
  suppressed_by_llm: boolean;
  evidence: Record<string, unknown>;
  source_event_id: string | null;
  source_log_type: string | null;
  source_timestamp: string | null;
  incident_id: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  mitre_techniques: string[];
  affected_assets: string[];
  alert_count: number;
  correlation_key: string | null;
  first_seen: string;
  last_seen: string;
  extra_data: Record<string, unknown> | null;
  created_at: string;
  updated_at: string | null;
}

export interface DetectionRule {
  id: string;
  rule_id: string;
  title: string;
  description: string | null;
  severity: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  rule_type: string;
  enabled: boolean;
  false_positive_rate: number;
  hit_count: number;
  extra_data: Record<string, unknown> | null;
  created_at: string;
  updated_at: string | null;
}

export interface AgentTask {
  id: string;
  incident_id: string;
  incident_title: string;
  severity: string;
  status: 'pending_approval' | 'approved' | 'executing' | 'completed' | 'failed' | 'cancelled' | 'rejected';
  triage: {
    urgency_score: number;
    attack_stage: string;
    recommended_response_tier: string;
    summary: string;
    key_indicators: string[];
  } | null;
  selected_playbook: string | null;
  playbook_steps: Array<{ action_type: string; target: string; order: number }> | null;
  actions_results: ActionResult[] | null;
  approval_notes: string | null;
  approved_by: string | null;
  approved_at: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface ActionResult {
  action_id: string;
  action_type: string;
  target: string;
  status: 'success' | 'failed' | 'skipped';
  result_data: Record<string, unknown>;
  duration_ms: number;
  executed_at: string;
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

export interface AnalyzeResult {
  alerts_created: number;
  alerts: Alert[];
}

// ── Fetch helper ───────────────────────────────────────────────────────────────

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json();
}

// ── Detection Engine ───────────────────────────────────────────────────────────

export const fetchStats = () =>
  apiFetch<DetectionStats>(`${DETECTION_URL}/api/v1/stats`);

export const fetchAlerts = (params?: {
  status?: string;
  severity?: string;
  skip?: number;
  limit?: number;
}) => {
  const q = new URLSearchParams();
  if (params?.status) q.set('status', params.status);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.skip !== undefined) q.set('skip', String(params.skip));
  if (params?.limit !== undefined) q.set('limit', String(params.limit));
  return apiFetch<Alert[]>(`${DETECTION_URL}/api/v1/alerts?${q}`);
};

export const fetchIncidents = (params?: { status?: string; severity?: string; skip?: number; limit?: number }) => {
  const q = new URLSearchParams();
  if (params?.status) q.set('status', params.status);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.skip !== undefined) q.set('skip', String(params.skip));
  if (params?.limit !== undefined) q.set('limit', String(params.limit));
  return apiFetch<Incident[]>(`${DETECTION_URL}/api/v1/incidents?${q}`);
};

export const fetchRules = (params?: { enabled?: boolean; rule_type?: string }) => {
  const q = new URLSearchParams();
  if (params?.enabled !== undefined) q.set('enabled', String(params.enabled));
  if (params?.rule_type) q.set('rule_type', params.rule_type);
  return apiFetch<DetectionRule[]>(`${DETECTION_URL}/api/v1/rules?${q}`);
};

export const updateRule = (ruleId: string, data: { enabled?: boolean; severity?: string }) =>
  apiFetch<DetectionRule>(`${DETECTION_URL}/api/v1/rules/${ruleId}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });

export const analyzeEvent = (event: Record<string, unknown>) =>
  apiFetch<AnalyzeResult>(`${DETECTION_URL}/api/v1/events/analyze`, {
    method: 'POST',
    body: JSON.stringify(event),
  });

// ── Agent Orchestrator ─────────────────────────────────────────────────────────

export const fetchAgentStats = () =>
  apiFetch<AgentStats>(`${AGENT_URL}/stats`);

export const fetchTasks = (params?: { status?: string; severity?: string; skip?: number; limit?: number }) => {
  const q = new URLSearchParams();
  if (params?.status) q.set('status', params.status);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.skip !== undefined) q.set('skip', String(params.skip));
  if (params?.limit !== undefined) q.set('limit', String(params.limit));
  return apiFetch<AgentTask[]>(`${AGENT_URL}/api/v1/tasks?${q}`);
};

export const fetchTask = (taskId: string) =>
  apiFetch<AgentTask>(`${AGENT_URL}/api/v1/tasks/${taskId}`);

export const fetchTaskActions = (taskId: string) =>
  apiFetch<ActionLog[]>(`${AGENT_URL}/api/v1/tasks/${taskId}/actions`);

export const approveTask = (taskId: string, data: { notes: string; approved_by: string }) =>
  apiFetch<AgentTask>(`${AGENT_URL}/api/v1/tasks/${taskId}/approve`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });

export const rejectTask = (taskId: string, data: { notes: string }) =>
  apiFetch<AgentTask>(`${AGENT_URL}/api/v1/tasks/${taskId}/reject`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });

export const analyzeIncident = (incident: Record<string, unknown>) =>
  apiFetch<AgentTask>(`${AGENT_URL}/api/v1/incidents/analyze`, {
    method: 'POST',
    body: JSON.stringify(incident),
  });

export const fetchPlaybooks = () =>
  apiFetch<Record<string, unknown>[]>(`${AGENT_URL}/api/v1/playbooks`);

// ── Utilities ──────────────────────────────────────────────────────────────────

export function timeAgo(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: '#ff4444',
    high: '#ff8800',
    medium: '#f59e0b',
    low: '#00ff88',
    info: '#00d4ff',
  };
  return map[severity?.toLowerCase()] || '#64748b';
}

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    open: '#ff4444',
    in_progress: '#ff8800',
    investigating: '#ff8800',
    resolved: '#00ff88',
    contained: '#00ff88',
    suppressed: '#64748b',
    closed: '#64748b',
    pending_approval: '#f59e0b',
    approved: '#00d4ff',
    executing: '#a855f7',
    completed: '#00ff88',
    failed: '#ff4444',
    cancelled: '#64748b',
    rejected: '#ff4444',
  };
  return map[status?.toLowerCase()] || '#64748b';
}

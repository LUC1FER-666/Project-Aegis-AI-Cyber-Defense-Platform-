// ─────────────────────────────────────────────────────────────────────────────
// Milestone 7 additions — append these to your existing src/lib/api.ts
// ─────────────────────────────────────────────────────────────────────────────

const TIMELINE_URL = 'http://localhost:8007';

// ─── Timeline types ───────────────────────────────────────────────────────────

export interface TimelineEvent {
  event_id: string;
  event_type: 'alert' | 'incident' | 'agent_task' | 'prediction' | 'narrative' | 'preemptive_action';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  source_service: string;
  source_id: string;
  asset_ids: string[];
  mitre_techniques: string[];
  extra_data: Record<string, unknown> | null;
  timestamp: string;
  created_at: string;
}

export interface TimelineStats {
  total_events: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  events_last_hour: number;
  events_last_24h: number;
}

// ─── Graph types ──────────────────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  type: 'Asset' | 'Alert' | 'Incident' | 'Technique' | 'AgentTask';
  label: string;
  severity: string;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  properties: Record<string, unknown>;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: { node_count: number; edge_count: number };
  warning?: string;
}

// ─── Timeline API calls ───────────────────────────────────────────────────────

export async function getTimeline(params?: {
  limit?: number;
  event_type?: string;
  severity?: string;
  asset_id?: string;
}): Promise<TimelineEvent[]> {
  const q = new URLSearchParams();
  if (params?.limit) q.set('limit', String(params.limit));
  if (params?.event_type) q.set('event_type', params.event_type);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.asset_id) q.set('asset_id', params.asset_id);
  const res = await fetch(`${TIMELINE_URL}/api/v1/timeline?${q}`);
  if (!res.ok) throw new Error(`Timeline API ${res.status}`);
  return res.json();
}

export async function getTimelineStats(): Promise<TimelineStats> {
  const res = await fetch(`${TIMELINE_URL}/api/v1/timeline/stats`);
  if (!res.ok) throw new Error(`Timeline stats API ${res.status}`);
  return res.json();
}

export function createTimelineEventSource(): EventSource {
  return new EventSource(`${TIMELINE_URL}/api/v1/timeline/stream`);
}

// ─── Graph API calls ──────────────────────────────────────────────────────────

export async function getGraphExport(): Promise<GraphResponse> {
  const res = await fetch(`${TIMELINE_URL}/api/v1/graph/export`);
  if (!res.ok) throw new Error(`Graph export API ${res.status}`);
  return res.json();
}

export async function getGraphOverview(): Promise<GraphResponse> {
  const res = await fetch(`${TIMELINE_URL}/api/v1/graph/overview`);
  if (!res.ok) throw new Error(`Graph overview API ${res.status}`);
  return res.json();
}

export async function getGraphForAsset(assetId: string): Promise<GraphResponse> {
  const res = await fetch(`${TIMELINE_URL}/api/v1/graph/asset/${encodeURIComponent(assetId)}`);
  if (!res.ok) throw new Error(`Graph asset API ${res.status}`);
  return res.json();
}

export async function getGraphForIncident(incidentId: string): Promise<GraphResponse> {
  const res = await fetch(`${TIMELINE_URL}/api/v1/graph/incident/${encodeURIComponent(incidentId)}`);
  if (!res.ok) throw new Error(`Graph incident API ${res.status}`);
  return res.json();
}

export async function getBlastRadius(assetId: string): Promise<GraphResponse> {
  const res = await fetch(`${TIMELINE_URL}/api/v1/graph/blast-radius/${encodeURIComponent(assetId)}`);
  if (!res.ok) throw new Error(`Blast radius API ${res.status}`);
  return res.json();
}

export async function getAttackPaths(): Promise<GraphResponse> {
  const res = await fetch(`${TIMELINE_URL}/api/v1/graph/attack-paths`);
  if (!res.ok) throw new Error(`Attack paths API ${res.status}`);
  return res.json();
}

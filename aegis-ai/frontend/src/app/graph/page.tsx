'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface GNode {
  id: string;
  type: string;
  label: string;
  severity: string;
  properties: Record<string, unknown>;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
  degree?: number;
}

interface GEdge {
  source: string | GNode;
  target: string | GNode;
  type: string;
}

interface GraphResponse {
  nodes: GNode[];
  edges: GEdge[];
  stats: { node_count: number; edge_count: number };
  warning?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const NODE_COLORS: Record<string, string> = {
  Asset: '#00d4ff',
  Alert: '#ff4444',
  Incident: '#ff8800',
  Technique: '#f59e0b',
  AgentTask: '#00ff88',
};
const NODE_TYPES = ['Asset', 'Alert', 'Incident', 'Technique', 'AgentTask'];
const API = 'http://localhost:8007';

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function GraphPage() {
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<{ stop: () => void } | null>(null);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<GNode | null>(null);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [d3Loaded, setD3Loaded] = useState(false);

  // Load D3 once from CDN
  useEffect(() => {
    if (document.getElementById('d3-script')) { setD3Loaded(true); return; }
    const s = document.createElement('script');
    s.id = 'd3-script';
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js';
    s.onload = () => setD3Loaded(true);
    document.head.appendChild(s);
  }, []);

  const fetchGraph = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const r = await fetch(`${API}/api/v1/graph/export`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setGraph(await r.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load graph');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchGraph(); }, [fetchGraph]);

  // Draw whenever graph or filters change, and D3 is available
  useEffect(() => {
    if (!graph || !svgRef.current || !d3Loaded) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const d3 = (window as any).d3;
    if (!d3) return;
    if (simRef.current) { simRef.current.stop(); }
    simRef.current = drawGraph(graph, svgRef.current, hidden, setSelected, d3);
  }, [graph, hidden, d3Loaded]);

  const toggleHide = (t: string) =>
    setHidden(s => { const n = new Set(s); n.has(t) ? n.delete(t) : n.add(t); return n; });

  const topAsset = graph?.nodes
    .filter(n => n.type === 'Asset')
    .sort((a, b) => (b.degree ?? 0) - (a.degree ?? 0))[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      {/* ── Top bar ── */}
      <div style={{
        padding: '10px 20px', borderBottom: '1px solid #1f2937',
        background: '#0a0f1e', display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0,
      }}>
        <div style={{ marginRight: 8 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#e5e7eb' }}>Attack Graph</div>
          <div style={{ fontSize: 11, color: '#6b7280' }}>Neo4j-backed interactive threat landscape</div>
        </div>

        {graph && (
          <>
            <Stat label="Nodes" value={graph.stats.node_count} color="#00d4ff" />
            <Stat label="Edges" value={graph.stats.edge_count} color="#00ff88" />
            {topAsset && <Stat label="Top Asset" value={topAsset.label.slice(0, 16)} color="#ff8800" />}
          </>
        )}

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Type toggles */}
          {NODE_TYPES.map(t => (
            <button key={t} onClick={() => toggleHide(t)} style={{
              padding: '3px 9px', fontSize: 11, borderRadius: 4, cursor: 'pointer',
              border: `1px solid ${hidden.has(t) ? '#374151' : NODE_COLORS[t]}`,
              background: hidden.has(t) ? 'transparent' : `${NODE_COLORS[t]}22`,
              color: hidden.has(t) ? '#4b5563' : NODE_COLORS[t],
            }}>{t}</button>
          ))}
          <button onClick={fetchGraph} disabled={loading} style={{
            padding: '6px 14px', borderRadius: 6, border: '1px solid #00d4ff',
            background: 'rgba(0,212,255,0.1)', color: '#00d4ff',
            cursor: loading ? 'not-allowed' : 'pointer', fontSize: 13,
          }}>
            {loading ? '⟳' : '↻ Refresh'}
          </button>
        </div>
      </div>

      {/* ── Warning ── */}
      {graph?.warning && (
        <div style={{
          padding: '7px 20px', background: 'rgba(255,136,0,0.08)',
          color: '#ff8800', fontSize: 12, borderBottom: '1px solid rgba(255,136,0,0.2)',
        }}>⚠️ {graph.warning}</div>
      )}

      {/* ── Canvas area ── */}
      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {loading && <Overlay><Spinner />Building graph…</Overlay>}
        {!loading && error && <Empty icon="⚠️" msg={error} sub="Is the Timeline service running on port 8007?" />}
        {!loading && !error && graph?.nodes.length === 0 && (
          <Empty icon="🕸️" msg="No graph data yet" sub="Alerts and incidents will appear as they're detected." />
        )}

        <svg ref={svgRef} width="100%" height="100%" style={{ display: 'block', background: '#050a14' }} />

        {/* Legend */}
        <div style={{
          position: 'absolute', bottom: 16, left: 16, background: 'rgba(10,15,30,0.92)',
          border: '1px solid #1f2937', borderRadius: 8, padding: '10px 14px',
        }}>
          {NODE_TYPES.map(t => (
            <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 3 }}>
              <span style={{ width: 9, height: 9, borderRadius: '50%', background: NODE_COLORS[t], display: 'inline-block' }} />
              <span style={{ fontSize: 11, color: '#9ca3af' }}>{t}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Node detail panel ── */}
      {selected && (
        <NodePanel node={selected} graph={graph} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

// ─── Small helpers ────────────────────────────────────────────────────────────

function Stat({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div style={{
      padding: '5px 12px', borderRadius: 6, textAlign: 'center',
      background: 'rgba(255,255,255,0.03)', border: `1px solid ${color}33`,
    }}>
      <div style={{ fontSize: 15, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase' }}>{label}</div>
    </div>
  );
}

function Overlay({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', gap: 12,
      color: '#6b7280', fontSize: 15, zIndex: 5, background: '#0a0f1e',
    }}>{children}</div>
  );
}

function Spinner() {
  return (
    <span style={{ fontSize: 28, display: 'inline-block', animation: 'spin 1s linear infinite' }}>
      ⟳
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </span>
  );
}

function Empty({ icon, msg, sub }: { icon: string; msg: string; sub: string }) {
  return (
    <div style={{
      position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', gap: 8, color: '#6b7280',
    }}>
      <div style={{ fontSize: 44 }}>{icon}</div>
      <div style={{ fontSize: 15, fontWeight: 600, color: '#9ca3af' }}>{msg}</div>
      <div style={{ fontSize: 12, maxWidth: 360, textAlign: 'center', lineHeight: 1.6 }}>{sub}</div>
    </div>
  );
}

function NodePanel({ node, graph, onClose }: { node: GNode; graph: GraphResponse | null; onClose: () => void }) {
  const color = NODE_COLORS[node.type] ?? '#6b7280';

  const related = (graph?.edges ?? []).flatMap(e => {
    const src = typeof e.source === 'string' ? e.source : (e.source as GNode).id;
    const dst = typeof e.target === 'string' ? e.target : (e.target as GNode).id;
    if (src !== node.id && dst !== node.id) return [];
    const otherId = src === node.id ? dst : src;
    const other = graph?.nodes.find(n => n.id === otherId);
    return other ? [{ relType: e.type, node: other }] : [];
  });

  return (
    <div style={{
      position: 'absolute', top: 0, right: 0, width: 300, height: '100%',
      background: '#0d1526', borderLeft: '1px solid #1f2937', overflowY: 'auto', zIndex: 30, padding: 18,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
        <span style={{
          fontSize: 10, padding: '2px 8px', borderRadius: 3, textTransform: 'uppercase',
          background: `${color}22`, color, border: `1px solid ${color}`,
        }}>{node.type}</span>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: 18 }}>✕</button>
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 700, color: '#e5e7eb', marginBottom: 14, wordBreak: 'break-word' }}>
        {node.label}
      </h3>

      <div style={{ marginBottom: 18 }}>
        <div style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', marginBottom: 8 }}>Properties</div>
        {Object.entries(node.properties)
          .filter(([, v]) => v !== null && v !== '' && v !== undefined)
          .slice(0, 12)
          .map(([k, v]) => (
            <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 5, fontSize: 12 }}>
              <span style={{ color: '#6b7280', minWidth: 100, flexShrink: 0 }}>{k}</span>
              <span style={{ color: '#e5e7eb', wordBreak: 'break-all' }}>
                {String(v).slice(0, 45)}{String(v).length > 45 ? '…' : ''}
              </span>
            </div>
          ))}
      </div>

      {related.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', marginBottom: 8 }}>
            Connections ({related.length})
          </div>
          {related.slice(0, 8).map((r, i) => (
            <div key={i} style={{
              padding: '7px 10px', background: 'rgba(255,255,255,0.02)',
              borderRadius: 6, marginBottom: 5, border: '1px solid #1f2937',
            }}>
              <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>{r.relType}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: NODE_COLORS[r.node.type] ?? '#6b7280', flexShrink: 0 }} />
                <span style={{ fontSize: 12, color: '#e5e7eb', wordBreak: 'break-all' }}>{r.node.label}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── D3 draw function ─────────────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function drawGraph(
  graph: GraphResponse,
  svgEl: SVGSVGElement,
  hidden: Set<string>,
  onSelect: (n: GNode) => void,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  d3: any,
): { stop: () => void } {
  const W = svgEl.clientWidth || 900;
  const H = svgEl.clientHeight || 600;

  const nodes: GNode[] = graph.nodes
    .filter(n => !hidden.has(n.type))
    .map(n => ({ ...n }));

  const nodeIds = new Set(nodes.map(n => n.id));
  const edges = graph.edges
    .filter(e => {
      const s = typeof e.source === 'string' ? e.source : (e.source as GNode).id;
      const t = typeof e.target === 'string' ? e.target : (e.target as GNode).id;
      return nodeIds.has(s) && nodeIds.has(t);
    })
    .map(e => ({ ...e }));

  // Degree
  const deg: Record<string, number> = {};
  edges.forEach(e => {
    const s = typeof e.source === 'string' ? e.source : (e.source as GNode).id;
    const t = typeof e.target === 'string' ? e.target : (e.target as GNode).id;
    deg[s] = (deg[s] ?? 0) + 1;
    deg[t] = (deg[t] ?? 0) + 1;
  });
  nodes.forEach(n => { n.degree = deg[n.id] ?? 0; });

  // Clear
  d3.select(svgEl).selectAll('*').remove();

  if (nodes.length === 0) return { stop: () => {} };

  const svg = d3.select(svgEl);

  // Zoom
  const g = svg.append('g');
  const zoom = d3.zoom().scaleExtent([0.1, 8]).on('zoom', (event: { transform: unknown }) => {
    g.attr('transform', event.transform);
  });
  svg.call(zoom);

  // Sim
  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id((n: GNode) => n.id).distance(80))
    .force('charge', d3.forceManyBody().strength(-280))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collide', d3.forceCollide(28));

  // Edges
  const link = g.append('g').attr('stroke', '#1e293b').attr('stroke-opacity', 0.7)
    .selectAll('line')
    .data(edges)
    .join('line')
    .attr('stroke-width', 1.5);

  // Edge labels (only if < 60 edges, for legibility)
  if (edges.length < 60) {
    g.append('g').attr('font-size', 8).attr('fill', '#374151')
      .selectAll('text')
      .data(edges)
      .join('text')
      .text((e: GEdge) => e.type);
  }

  // Nodes (group)
  const node = g.append('g')
    .selectAll('g')
    .data(nodes)
    .join('g')
    .style('cursor', 'pointer')
    .on('click', (_: MouseEvent, n: GNode) => onSelect(n))
    .call(
      d3.drag()
        .on('start', (event: { active: boolean; subject: GNode }) => {
          if (!event.active) sim.alphaTarget(0.3).restart();
          event.subject.fx = event.subject.x;
          event.subject.fy = event.subject.y;
        })
        .on('drag', (event: { x: number; y: number; subject: GNode }) => {
          event.subject.fx = event.x;
          event.subject.fy = event.y;
        })
        .on('end', (event: { active: boolean; subject: GNode }) => {
          if (!event.active) sim.alphaTarget(0);
          event.subject.fx = null;
          event.subject.fy = null;
        })
    );

  node.append('circle')
    .attr('r', (n: GNode) => 7 + Math.min((n.degree ?? 0) * 2.5, 18))
    .attr('fill', (n: GNode) => NODE_COLORS[n.type] ?? '#6b7280')
    .attr('fill-opacity', 0.85)
    .attr('stroke', (n: GNode) => NODE_COLORS[n.type] ?? '#6b7280')
    .attr('stroke-width', 2)
    .attr('stroke-opacity', 0.4);

  node.append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', (n: GNode) => 7 + Math.min((n.degree ?? 0) * 2.5, 18) + 13)
    .attr('font-size', 9)
    .attr('fill', '#9ca3af')
    .text((n: GNode) => n.label.slice(0, 18));

  // Tooltip on hover
  node.append('title').text((n: GNode) => `${n.type}: ${n.label}`);

  // Tick
  sim.on('tick', () => {
    link
      .attr('x1', (e: { source: GNode }) => e.source.x ?? 0)
      .attr('y1', (e: { source: GNode }) => e.source.y ?? 0)
      .attr('x2', (e: { target: GNode }) => e.target.x ?? 0)
      .attr('y2', (e: { target: GNode }) => e.target.y ?? 0);

    node.attr('transform', (n: GNode) => `translate(${n.x ?? 0},${n.y ?? 0})`);

    if (edges.length < 60) {
      g.selectAll('text').filter(function(this: SVGTextElement) {
        return !this.closest('g[data-node]');
      })
        .attr('x', (e: { source: GNode; target: GNode }) => ((e.source.x ?? 0) + (e.target.x ?? 0)) / 2)
        .attr('y', (e: { source: GNode; target: GNode }) => ((e.source.y ?? 0) + (e.target.y ?? 0)) / 2);
    }
  });

  return { stop: () => sim.stop() };
}

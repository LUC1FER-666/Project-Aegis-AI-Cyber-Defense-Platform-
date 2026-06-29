'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

// ─── Types ──────────────────────────────────────────────────────────────────

interface TimelineEvent {
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

// ─── Constants ───────────────────────────────────────────────────────────────

const EVENT_ICONS: Record<string, string> = {
  alert: '⚡',
  incident: '🔴',
  agent_task: '⚙️',
  prediction: '⚠️',
  narrative: '📋',
  preemptive_action: '🛡️',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4444',
  high: '#ff8800',
  medium: '#f59e0b',
  low: '#3b82f6',
  info: '#6b7280',
};

const SEVERITY_BG: Record<string, string> = {
  critical: 'rgba(255,68,68,0.08)',
  high: 'rgba(255,136,0,0.08)',
  medium: 'rgba(245,158,11,0.08)',
  low: 'rgba(59,130,246,0.08)',
  info: 'rgba(107,114,128,0.08)',
};

const EVENT_TYPES = ['alert', 'incident', 'agent_task', 'prediction', 'narrative', 'preemptive_action'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const TIMELINE_URL = 'http://localhost:8007';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function timeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      style={{
        background: SEVERITY_BG[severity] || SEVERITY_BG.info,
        color: SEVERITY_COLORS[severity] || SEVERITY_COLORS.info,
        border: `1px solid ${SEVERITY_COLORS[severity] || SEVERITY_COLORS.info}`,
        padding: '1px 8px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 700,
        textTransform: 'uppercase',
      }}
    >
      {severity}
    </span>
  );
}

function EventCard({ event, isNew }: { event: TimelineEvent; isNew: boolean }) {
  const borderColor = SEVERITY_COLORS[event.severity] || SEVERITY_COLORS.info;
  const icon = EVENT_ICONS[event.event_type] || '📌';

  return (
    <div
      style={{
        display: 'flex',
        gap: 16,
        padding: '14px 16px',
        background: isNew ? 'rgba(0,212,255,0.04)' : 'rgba(255,255,255,0.02)',
        borderRadius: 8,
        borderLeft: `3px solid ${borderColor}`,
        marginBottom: 8,
        transition: 'background 0.6s ease',
        animation: isNew ? 'slideIn 0.4s ease' : 'none',
      }}
    >
      {/* Icon */}
      <div style={{ fontSize: 20, flexShrink: 0, paddingTop: 2 }}>{icon}</div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
          <SeverityBadge severity={event.severity} />
          <span
            style={{
              fontSize: 11,
              color: '#6b7280',
              background: 'rgba(255,255,255,0.05)',
              padding: '1px 6px',
              borderRadius: 3,
              textTransform: 'uppercase',
            }}
          >
            {event.event_type.replace('_', ' ')}
          </span>
          <span style={{ fontSize: 11, color: '#4b5563', marginLeft: 'auto' }}>
            {timeAgo(event.timestamp)}
          </span>
        </div>

        <div style={{ fontSize: 14, fontWeight: 600, color: '#e5e7eb', marginBottom: 4, wordBreak: 'break-word' }}>
          {event.title}
        </div>

        <div style={{ fontSize: 12, color: '#9ca3af', marginBottom: 8, lineHeight: 1.5 }}>
          {event.description}
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {event.asset_ids.slice(0, 3).map((id) => (
            <span
              key={id}
              style={{
                fontSize: 10,
                padding: '2px 6px',
                background: 'rgba(0,212,255,0.1)',
                color: '#00d4ff',
                borderRadius: 3,
                border: '1px solid rgba(0,212,255,0.2)',
              }}
            >
              📦 {id.length > 20 ? id.slice(0, 20) + '…' : id}
            </span>
          ))}
          {event.mitre_techniques.slice(0, 3).map((t) => (
            <span
              key={t}
              style={{
                fontSize: 10,
                padding: '2px 6px',
                background: 'rgba(245,158,11,0.1)',
                color: '#f59e0b',
                borderRadius: 3,
                border: '1px solid rgba(245,158,11,0.2)',
              }}
            >
              🎯 {t}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function TimelinePage() {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [newEventIds, setNewEventIds] = useState<Set<string>>(new Set());
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set());
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [assetSearch, setAssetSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const eventsRef = useRef(events);
  const pausedRef = useRef(paused);
  eventsRef.current = events;
  pausedRef.current = paused;

  // Load initial events
  useEffect(() => {
    const params = new URLSearchParams({ limit: '100' });
    fetch(`${TIMELINE_URL}/api/v1/timeline?${params}`)
      .then((r) => r.json())
      .then((data: TimelineEvent[]) => {
        setEvents(data);
        setLoading(false);
      })
      .catch((e) => {
        setError(`Failed to load timeline: ${e.message}`);
        setLoading(false);
      });
  }, []);

  // SSE stream
  useEffect(() => {
    const es = new EventSource(`${TIMELINE_URL}/api/v1/timeline/stream`);

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    es.onmessage = (e) => {
      if (pausedRef.current) return;
      try {
        const ev: TimelineEvent = JSON.parse(e.data);
        setEvents((prev) => {
          if (prev.some((p) => p.event_id === ev.event_id)) return prev;
          return [ev, ...prev].slice(0, 200);
        });
        setNewEventIds((s) => {
          const next = new Set(s);
          next.add(ev.event_id);
          return next;
        });
        // Clear "new" flash after 3s
        setTimeout(() => {
          setNewEventIds((s) => {
            const next = new Set(s);
            next.delete(ev.event_id);
            return next;
          });
        }, 3000);
      } catch {
        // ignore parse errors
      }
    };

    return () => es.close();
  }, []);

  // Filtered events
  const filtered = events.filter((ev) => {
    if (selectedTypes.size > 0 && !selectedTypes.has(ev.event_type)) return false;
    if (selectedSeverity && ev.severity !== selectedSeverity) return false;
    if (assetSearch && !ev.asset_ids.some((id) => id.toLowerCase().includes(assetSearch.toLowerCase()))) return false;
    return true;
  });

  const toggleType = (t: string) => {
    setSelectedTypes((s) => {
      const next = new Set(s);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: 900, margin: '0 auto' }}>
      <style>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(-12px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: '#e5e7eb', margin: 0 }}>
            Live Attack Timeline
          </h1>
          <p style={{ color: '#6b7280', fontSize: 13, margin: '4px 0 0' }}>
            Unified chronological view of all security events
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* SSE status */}
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: connected ? '#00ff88' : '#ff4444',
                display: 'inline-block',
                boxShadow: connected ? '0 0 6px #00ff88' : 'none',
              }}
            />
            <span style={{ color: '#9ca3af' }}>{connected ? 'Live' : 'Disconnected'}</span>
          </span>

          {/* Pause toggle */}
          <button
            onClick={() => setPaused((p) => !p)}
            style={{
              padding: '6px 16px',
              borderRadius: 6,
              border: `1px solid ${paused ? '#ff4444' : '#374151'}`,
              background: paused ? 'rgba(255,68,68,0.1)' : 'rgba(255,255,255,0.05)',
              color: paused ? '#ff4444' : '#9ca3af',
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            {paused ? '▶ Resume' : '⏸ Pause Feed'}
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
        {['critical', 'high', 'medium', 'low'].map((sev) => {
          const count = events.filter((e) => e.severity === sev).length;
          return (
            <div
              key={sev}
              style={{
                padding: '8px 16px',
                borderRadius: 6,
                background: 'rgba(255,255,255,0.03)',
                border: `1px solid ${SEVERITY_COLORS[sev]}33`,
                textAlign: 'center',
                minWidth: 80,
              }}
            >
              <div style={{ fontSize: 20, fontWeight: 700, color: SEVERITY_COLORS[sev] }}>{count}</div>
              <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase' }}>{sev}</div>
            </div>
          );
        })}
        <div
          style={{
            padding: '8px 16px',
            borderRadius: 6,
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid #374151',
            textAlign: 'center',
            minWidth: 80,
          }}
        >
          <div style={{ fontSize: 20, fontWeight: 700, color: '#e5e7eb' }}>{events.length}</div>
          <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase' }}>Total</div>
        </div>
      </div>

      {/* Filters */}
      <div
        style={{
          padding: '12px 16px',
          background: 'rgba(255,255,255,0.02)',
          border: '1px solid #1f2937',
          borderRadius: 8,
          marginBottom: 20,
          display: 'flex',
          gap: 12,
          flexWrap: 'wrap',
          alignItems: 'center',
        }}
      >
        {/* Type filter */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {EVENT_TYPES.map((t) => (
            <button
              key={t}
              onClick={() => toggleType(t)}
              style={{
                padding: '3px 10px',
                borderRadius: 4,
                fontSize: 11,
                border: `1px solid ${selectedTypes.has(t) ? '#00d4ff' : '#374151'}`,
                background: selectedTypes.has(t) ? 'rgba(0,212,255,0.1)' : 'transparent',
                color: selectedTypes.has(t) ? '#00d4ff' : '#6b7280',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 4,
              }}
            >
              {EVENT_ICONS[t]} {t.replace('_', ' ')}
            </button>
          ))}
        </div>

        <div style={{ width: 1, height: 24, background: '#1f2937' }} />

        {/* Severity filter */}
        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value)}
          style={{
            background: '#111827',
            border: '1px solid #374151',
            color: '#9ca3af',
            padding: '4px 8px',
            borderRadius: 4,
            fontSize: 12,
          }}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        {/* Asset search */}
        <input
          placeholder="Search asset ID..."
          value={assetSearch}
          onChange={(e) => setAssetSearch(e.target.value)}
          style={{
            background: '#111827',
            border: '1px solid #374151',
            color: '#e5e7eb',
            padding: '4px 12px',
            borderRadius: 4,
            fontSize: 12,
            outline: 'none',
            width: 160,
          }}
        />

        {(selectedTypes.size > 0 || selectedSeverity || assetSearch) && (
          <button
            onClick={() => { setSelectedTypes(new Set()); setSelectedSeverity(''); setAssetSearch(''); }}
            style={{
              fontSize: 11,
              color: '#ff4444',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              padding: '0 4px',
            }}
          >
            ✕ Clear
          </button>
        )}

        <span style={{ marginLeft: 'auto', fontSize: 12, color: '#6b7280' }}>
          {filtered.length} events
        </span>
      </div>

      {/* Timeline */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 60, color: '#6b7280' }}>Loading timeline…</div>
      ) : error ? (
        <div
          style={{
            textAlign: 'center',
            padding: 60,
            color: '#ff4444',
            background: 'rgba(255,68,68,0.05)',
            borderRadius: 8,
            border: '1px solid rgba(255,68,68,0.2)',
          }}
        >
          {error}
          <div style={{ fontSize: 12, color: '#6b7280', marginTop: 8 }}>
            Make sure the Timeline service is running on port 8007
          </div>
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 60, color: '#6b7280' }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>📭</div>
          <div>No events match your filters</div>
        </div>
      ) : (
        <div>
          {filtered.map((ev) => (
            <EventCard key={ev.event_id} event={ev} isNew={newEventIds.has(ev.event_id)} />
          ))}
        </div>
      )}
    </div>
  );
}

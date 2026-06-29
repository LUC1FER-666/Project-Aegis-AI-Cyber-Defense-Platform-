'use client';

import { severityColor, statusColor } from '@/lib/api';

// ── Severity Badge ─────────────────────────────────────────────────────────────

export function SeverityBadge({ severity }: { severity: string }) {
  const color = severityColor(severity);
  const bg = color + '22';
  const border = color + '44';
  return (
    <span
      className="tag font-mono"
      style={{ color, background: bg, border: `1px solid ${border}` }}
    >
      {severity?.toUpperCase()}
    </span>
  );
}

// ── Status Badge ───────────────────────────────────────────────────────────────

export function StatusBadge({ status }: { status: string }) {
  const color = statusColor(status);
  const bg = color + '22';
  const border = color + '44';
  const label = status?.replace(/_/g, ' ').toUpperCase();
  return (
    <span
      className="tag"
      style={{ color, background: bg, border: `1px solid ${border}` }}
    >
      {label}
    </span>
  );
}

// ── Metric Card ────────────────────────────────────────────────────────────────

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
  icon?: string;
  glow?: boolean;
}

export function MetricCard({ label, value, sub, color = '#00d4ff', icon, glow }: MetricCardProps) {
  const glowStyle = glow ? { boxShadow: `0 0 30px ${color}22, 0 0 60px ${color}0a` } : {};
  return (
    <div
      className="glass glass-hover rounded-xl p-5 cursor-default"
      style={{ borderColor: color + '33', ...glowStyle }}
    >
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: '#64748b' }}>
          {label}
        </span>
        {icon && <span className="text-xl">{icon}</span>}
      </div>
      <div className="text-3xl font-bold mb-1" style={{ color }}>
        {value}
      </div>
      {sub && <div className="text-xs" style={{ color: '#64748b' }}>{sub}</div>}
    </div>
  );
}

// ── Loading Skeleton ───────────────────────────────────────────────────────────

export function LoadingSkeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          {Array.from({ length: cols }).map((_, j) => (
            <div
              key={j}
              className="skeleton h-8 rounded"
              style={{ flex: j === 0 ? '0 0 80px' : 1, animationDelay: `${(i * cols + j) * 0.05}s` }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export function CardSkeleton() {
  return (
    <div className="glass rounded-xl p-5 space-y-3">
      <div className="skeleton h-4 w-24 rounded" />
      <div className="skeleton h-8 w-16 rounded" />
      <div className="skeleton h-3 w-32 rounded" />
    </div>
  );
}

// ── JSON Viewer ────────────────────────────────────────────────────────────────

export function JsonViewer({ data }: { data: unknown }) {
  if (data === null || data === undefined) return <span className="text-aegis-muted text-xs">null</span>;

  const json = JSON.stringify(data, null, 2);

  const highlighted = json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
      let cls = 'color:#a855f7'; // number
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'color:#00d4ff'; // key
        } else {
          cls = 'color:#00ff88'; // string
        }
      } else if (/true|false/.test(match)) {
        cls = 'color:#f59e0b'; // bool
      } else if (/null/.test(match)) {
        cls = 'color:#64748b'; // null
      }
      return `<span style="${cls}">${match}</span>`;
    });

  return (
    <pre
      className="font-mono text-xs leading-5 overflow-auto p-4 rounded-lg"
      style={{ background: '#020817', border: '1px solid #1a2744', maxHeight: '300px' }}
      dangerouslySetInnerHTML={{ __html: highlighted }}
    />
  );
}

// ── Empty State ────────────────────────────────────────────────────────────────

export function EmptyState({ icon, title, sub }: { icon: string; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3">
      <div className="text-5xl opacity-30">{icon}</div>
      <div className="text-sm font-medium" style={{ color: '#64748b' }}>{title}</div>
      {sub && <div className="text-xs" style={{ color: '#334155' }}>{sub}</div>}
    </div>
  );
}

// ── Section Header ─────────────────────────────────────────────────────────────

export function SectionHeader({ title, sub, count }: { title: string; sub?: string; count?: number }) {
  return (
    <div className="flex items-center justify-between mb-6">
      <div>
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          {title}
          {count !== undefined && (
            <span className="tag" style={{ background: '#00d4ff22', color: '#00d4ff', border: '1px solid #00d4ff44' }}>
              {count}
            </span>
          )}
        </h2>
        {sub && <p className="text-xs mt-1" style={{ color: '#64748b' }}>{sub}</p>}
      </div>
    </div>
  );
}

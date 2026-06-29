'use client';

import { useEffect, useState } from 'react';
import { fetchIncidents, type Incident, timeAgo, severityColor } from '@/lib/api';
import { SeverityBadge, StatusBadge, EmptyState, LoadingSkeleton } from '@/components';

const MITRE_DESCRIPTIONS: Record<string, string> = {
  'T1059': 'Command and Scripting Interpreter',
  'T1059.001': 'PowerShell Execution',
  'T1053': 'Scheduled Task/Job',
  'T1053.005': 'Scheduled Task',
  'T1110': 'Brute Force',
  'T1071': 'Application Layer Protocol',
  'T1071.004': 'DNS Tunneling',
  'T1571': 'Non-Standard Port',
  'T1021': 'Remote Services',
  'T1041': 'Exfiltration Over C2 Channel',
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [search, setSearch] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchIncidents({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        limit: 100,
      });
      setIncidents(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [statusFilter, severityFilter]);
  useEffect(() => {
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [statusFilter, severityFilter]);

  const filtered = search
    ? incidents.filter(i => i.title.toLowerCase().includes(search.toLowerCase()))
    : incidents;

  return (
    <div className="flex gap-6 h-full" style={{ minHeight: 'calc(100vh - 64px)' }}>
      {/* Main panel */}
      <div className="flex-1 space-y-6 min-w-0">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white mb-1">Incidents</h1>
            <p className="text-sm" style={{ color: '#64748b' }}>Correlated threat incidents</p>
          </div>
          <button className="btn btn-ghost text-xs" onClick={load}>↻ Refresh</button>
        </div>

        {/* Filters */}
        <div className="glass rounded-xl p-4 flex gap-3 flex-wrap">
          <input
            className="input text-sm"
            style={{ maxWidth: '220px' }}
            placeholder="Search incidents..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <select
            className="input text-sm"
            style={{ maxWidth: '150px' }}
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
          >
            <option value="">All Statuses</option>
            {['open', 'investigating', 'contained', 'resolved'].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
          <select
            className="input text-sm"
            style={{ maxWidth: '150px' }}
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            {['critical', 'high', 'medium', 'low'].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>

        {/* Incident Cards */}
        {error ? (
          <div className="glass rounded-xl p-8 text-center">
            <div className="text-sm" style={{ color: '#ff4444' }}>⚠ {error}</div>
          </div>
        ) : loading ? (
          <div className="grid grid-cols-1 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="glass rounded-xl p-6">
                <LoadingSkeleton rows={3} cols={3} />
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="glass rounded-xl">
            <EmptyState icon="🛡" title="No incidents found" sub="Incidents are created when multiple alerts correlate" />
          </div>
        ) : (
          <div className="space-y-4">
            {filtered.map(inc => {
              const isSelected = selected?.id === inc.id;
              const color = severityColor(inc.severity);
              const duration = Math.round((new Date(inc.last_seen).getTime() - new Date(inc.first_seen).getTime()) / 60000);

              return (
                <div
                  key={inc.id}
                  className="glass rounded-xl p-5 cursor-pointer transition-all duration-200"
                  style={{
                    borderColor: isSelected ? color + '66' : '#1a2744',
                    boxShadow: isSelected ? `0 0 20px ${color}22` : 'none',
                  }}
                  onClick={() => setSelected(isSelected ? null : inc)}
                  onMouseEnter={e => !isSelected && (e.currentTarget.style.borderColor = '#243354')}
                  onMouseLeave={e => !isSelected && (e.currentTarget.style.borderColor = '#1a2744')}
                >
                  <div className="flex items-start gap-4">
                    {/* Severity stripe */}
                    <div
                      className="w-1 rounded-full flex-shrink-0"
                      style={{ background: color, alignSelf: 'stretch', minHeight: '40px' }}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-3 mb-3">
                        <div className="flex-1 min-w-0">
                          <h3 className="text-sm font-semibold text-white leading-snug">{inc.title}</h3>
                          <div className="text-xs mt-1 space-x-3" style={{ color: '#64748b' }}>
                            <span>{inc.alert_count} alerts</span>
                            <span>·</span>
                            <span>{inc.affected_assets.length} asset{inc.affected_assets.length !== 1 ? 's' : ''}</span>
                            <span>·</span>
                            <span>{duration}m duration</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <SeverityBadge severity={inc.severity} />
                          <StatusBadge status={inc.status} />
                        </div>
                      </div>

                      {/* MITRE tags */}
                      <div className="flex flex-wrap gap-2 mb-3">
                        {inc.mitre_techniques.map(t => (
                          <span
                            key={t}
                            className="tag font-mono"
                            style={{ background: '#a855f722', color: '#a855f7', border: '1px solid #a855f744' }}
                            title={MITRE_DESCRIPTIONS[t]}
                          >
                            {t}
                          </span>
                        ))}
                        {inc.affected_assets.slice(0, 3).map(a => (
                          <span
                            key={a}
                            className="tag"
                            style={{ background: '#00d4ff11', color: '#00d4ff', border: '1px solid #00d4ff22' }}
                          >
                            {a}
                          </span>
                        ))}
                        {inc.affected_assets.length > 3 && (
                          <span className="tag" style={{ background: '#1a2744', color: '#64748b', border: '1px solid #243354' }}>
                            +{inc.affected_assets.length - 3} more
                          </span>
                        )}
                      </div>

                      {/* Timeline bar */}
                      <div className="flex items-center gap-3">
                        <span className="text-xs font-mono" style={{ color: '#334155' }}>
                          {new Date(inc.first_seen).toLocaleTimeString()}
                        </span>
                        <div className="flex-1 h-1 rounded-full" style={{ background: '#1a2744' }}>
                          <div
                            className="h-full rounded-full"
                            style={{ background: `linear-gradient(90deg, ${color}88, ${color})`, width: '100%' }}
                          />
                        </div>
                        <span className="text-xs font-mono" style={{ color: '#64748b' }}>
                          {timeAgo(inc.last_seen)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <div
          className="glass rounded-xl overflow-hidden flex-shrink-0"
          style={{ width: '380px', alignSelf: 'flex-start', position: 'sticky', top: '0' }}
        >
          <div
            className="px-5 py-4 flex items-center justify-between"
            style={{ borderBottom: '1px solid #1a2744', background: severityColor(selected.severity) + '11' }}
          >
            <div className="flex items-center gap-2">
              <SeverityBadge severity={selected.severity} />
              <StatusBadge status={selected.status} />
            </div>
            <button
              className="btn btn-ghost text-xs py-1 px-2"
              onClick={() => setSelected(null)}
            >
              ✕
            </button>
          </div>

          <div className="p-5 space-y-5 overflow-y-auto" style={{ maxHeight: '80vh' }}>
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">{selected.title}</h3>
              {selected.description && (
                <p className="text-xs leading-relaxed" style={{ color: '#64748b' }}>{selected.description}</p>
              )}
            </div>

            {/* Stats grid */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Alert Count', value: selected.alert_count },
                { label: 'Assets', value: selected.affected_assets.length },
                { label: 'First Seen', value: new Date(selected.first_seen).toLocaleTimeString() },
                { label: 'Last Seen', value: timeAgo(selected.last_seen) },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg p-3" style={{ background: '#020817', border: '1px solid #1a2744' }}>
                  <div className="text-xs mb-1" style={{ color: '#64748b' }}>{label}</div>
                  <div className="text-sm font-semibold text-white">{value}</div>
                </div>
              ))}
            </div>

            {/* MITRE Techniques */}
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748b' }}>
                MITRE Techniques
              </div>
              <div className="space-y-2">
                {selected.mitre_techniques.map(t => (
                  <div key={t} className="flex items-center gap-3 p-2.5 rounded-lg" style={{ background: '#020817', border: '1px solid #a855f722' }}>
                    <span className="tag font-mono" style={{ background: '#a855f722', color: '#a855f7', border: '1px solid #a855f744' }}>{t}</span>
                    <span className="text-xs" style={{ color: '#64748b' }}>{MITRE_DESCRIPTIONS[t] || 'Unknown technique'}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Affected Assets */}
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748b' }}>
                Affected Assets
              </div>
              <div className="space-y-1.5">
                {selected.affected_assets.map(a => (
                  <div
                    key={a}
                    className="flex items-center gap-2 p-2.5 rounded-lg text-sm"
                    style={{ background: '#020817', border: '1px solid #1a2744', color: '#00d4ff' }}
                  >
                    <span style={{ color: '#334155' }}>▸</span>
                    <span className="font-mono text-xs">{a}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Correlation key */}
            {selected.correlation_key && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: '#64748b' }}>
                  Correlation Key
                </div>
                <div className="font-mono text-xs p-2.5 rounded-lg" style={{ background: '#020817', border: '1px solid #1a2744', color: '#64748b' }}>
                  {selected.correlation_key}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

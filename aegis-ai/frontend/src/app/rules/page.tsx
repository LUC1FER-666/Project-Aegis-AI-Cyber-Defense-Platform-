'use client';

import { useEffect, useState } from 'react';
import { fetchRules, updateRule, type DetectionRule, timeAgo } from '@/lib/api';
import { SeverityBadge, EmptyState, LoadingSkeleton } from '@/components';

export default function RulesPage() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<DetectionRule | null>(null);
  const [toggling, setToggling] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const data = await fetchRules();
      setRules(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleToggle = async (rule: DetectionRule) => {
    setToggling(rule.rule_id);
    try {
      const updated = await updateRule(rule.rule_id, { enabled: !rule.enabled });
      setRules(prev => prev.map(r => r.rule_id === rule.rule_id ? updated : r));
      if (selected?.rule_id === rule.rule_id) setSelected(updated);
    } finally {
      setToggling(null);
    }
  };

  const filtered = rules.filter(r => {
    const matchText = !filter || r.title.toLowerCase().includes(filter.toLowerCase()) ||
      r.rule_id.toLowerCase().includes(filter.toLowerCase()) ||
      (r.mitre_technique || '').toLowerCase().includes(filter.toLowerCase());
    const matchType = !typeFilter || r.rule_type === typeFilter;
    return matchText && matchType;
  });

  const enabledCount = rules.filter(r => r.enabled).length;
  const sigmaCount = rules.filter(r => r.rule_type === 'sigma').length;
  const mlCount = rules.filter(r => r.rule_type === 'ml').length;

  return (
    <div className="flex gap-6">
      <div className="flex-1 min-w-0 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white mb-1">Detection Rules</h1>
            <p className="text-sm" style={{ color: '#64748b' }}>Sigma rules and ML models</p>
          </div>
          <button className="btn btn-ghost text-xs" onClick={load}>↻ Refresh</button>
        </div>

        {/* Stats bar */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total Rules', value: rules.length, color: '#00d4ff' },
            { label: 'Enabled', value: enabledCount, color: '#00ff88' },
            { label: 'Sigma', value: sigmaCount, color: '#a855f7' },
            { label: 'ML Models', value: mlCount, color: '#f59e0b' },
          ].map(({ label, value, color }) => (
            <div key={label} className="glass rounded-xl p-4 text-center">
              <div className="text-2xl font-bold mb-1" style={{ color }}>{value}</div>
              <div className="text-xs" style={{ color: '#64748b' }}>{label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="glass rounded-xl p-4 flex gap-3">
          <input
            className="input text-sm"
            style={{ maxWidth: '260px' }}
            placeholder="Search rules..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
          />
          <select
            className="input text-sm"
            style={{ maxWidth: '150px' }}
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
          >
            <option value="">All Types</option>
            <option value="sigma">Sigma</option>
            <option value="ml">ML</option>
          </select>
        </div>

        {/* Rules table */}
        <div className="glass rounded-xl overflow-hidden">
          {loading ? (
            <div className="p-6"><LoadingSkeleton rows={6} cols={5} /></div>
          ) : filtered.length === 0 ? (
            <EmptyState icon="◈" title="No rules found" />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>MITRE</th>
                  <th>Type</th>
                  <th>Hits</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(rule => (
                  <tr
                    key={rule.rule_id}
                    onClick={() => setSelected(selected?.rule_id === rule.rule_id ? null : rule)}
                    style={{
                      cursor: 'pointer',
                      opacity: rule.enabled ? 1 : 0.5,
                      background: selected?.rule_id === rule.rule_id ? 'rgba(0,212,255,0.05)' : undefined,
                    }}
                  >
                    <td onClick={e => { e.stopPropagation(); handleToggle(rule); }}>
                      <div
                        className="relative inline-flex items-center cursor-pointer"
                        style={{ width: '36px', height: '20px' }}
                      >
                        <div
                          className="rounded-full transition-colors duration-200"
                          style={{
                            width: '36px',
                            height: '20px',
                            background: rule.enabled ? '#059669' : '#1a2744',
                            border: `1px solid ${rule.enabled ? '#00ff8844' : '#243354'}`,
                            boxShadow: rule.enabled ? '0 0 8px rgba(0,255,136,0.3)' : 'none',
                          }}
                        >
                          <div
                            className="absolute top-0.5 rounded-full transition-all duration-200"
                            style={{
                              width: '16px',
                              height: '16px',
                              background: 'white',
                              left: rule.enabled ? '18px' : '2px',
                              opacity: toggling === rule.rule_id ? 0.5 : 1,
                            }}
                          />
                        </div>
                      </div>
                    </td>
                    <td>
                      <div className="text-sm font-medium text-white">{rule.title}</div>
                      <div className="font-mono text-xs mt-0.5" style={{ color: '#334155' }}>
                        {rule.rule_id.slice(0, 28)}...
                      </div>
                    </td>
                    <td><SeverityBadge severity={rule.severity} /></td>
                    <td>
                      {rule.mitre_technique ? (
                        <span className="tag font-mono" style={{ background: '#a855f722', color: '#a855f7', border: '1px solid #a855f744' }}>
                          {rule.mitre_technique}
                        </span>
                      ) : <span style={{ color: '#334155' }}>—</span>}
                    </td>
                    <td>
                      <span
                        className="tag"
                        style={{
                          background: rule.rule_type === 'sigma' ? '#00d4ff11' : '#f59e0b11',
                          color: rule.rule_type === 'sigma' ? '#00d4ff' : '#f59e0b',
                          border: `1px solid ${rule.rule_type === 'sigma' ? '#00d4ff22' : '#f59e0b22'}`,
                        }}
                      >
                        {rule.rule_type}
                      </span>
                    </td>
                    <td>
                      <span
                        className="font-mono text-sm font-bold"
                        style={{ color: rule.hit_count > 0 ? '#ff8800' : '#334155' }}
                      >
                        {rule.hit_count}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs" style={{ color: '#64748b' }}>{timeAgo(rule.created_at)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div
          className="glass rounded-xl overflow-hidden flex-shrink-0"
          style={{ width: '320px', alignSelf: 'flex-start', position: 'sticky', top: '0' }}
        >
          <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid #1a2744' }}>
            <span className="text-sm font-semibold text-white">Rule Details</span>
            <button className="btn btn-ghost text-xs py-1 px-2" onClick={() => setSelected(null)}>✕</button>
          </div>
          <div className="p-5 space-y-4">
            <div>
              <div className="text-sm font-semibold text-white mb-1">{selected.title}</div>
              {selected.description && (
                <p className="text-xs leading-relaxed" style={{ color: '#64748b' }}>{selected.description}</p>
              )}
            </div>
            <div className="space-y-2 text-xs">
              {[
                { label: 'Rule ID', value: selected.rule_id, mono: true, color: '#00d4ff' },
                { label: 'Type', value: selected.rule_type },
                { label: 'Tactic', value: selected.mitre_tactic || '—' },
                { label: 'False Positive Rate', value: `${(selected.false_positive_rate * 100).toFixed(1)}%` },
                { label: 'Total Hits', value: String(selected.hit_count) },
              ].map(({ label, value, mono, color }) => (
                <div key={label} className="flex justify-between">
                  <span style={{ color: '#64748b' }}>{label}</span>
                  <span
                    className={mono ? 'font-mono' : ''}
                    style={{ color: color || '#e2e8f0' }}
                  >
                    {value}
                  </span>
                </div>
              ))}
            </div>
            <div className="flex items-center justify-between pt-2" style={{ borderTop: '1px solid #1a2744' }}>
              <span className="text-xs" style={{ color: '#64748b' }}>
                {selected.enabled ? 'Rule is active' : 'Rule is disabled'}
              </span>
              <button
                className={`btn text-xs ${selected.enabled ? 'btn-danger' : 'btn-success'}`}
                onClick={() => handleToggle(selected)}
                disabled={toggling === selected.rule_id}
              >
                {toggling === selected.rule_id ? '...' : selected.enabled ? 'Disable' : 'Enable'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

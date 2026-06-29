'use client';

import { useEffect, useState } from 'react';
import {
  fetchAlerts, type Alert, timeAgo, severityColor,
} from '@/lib/api';
import { SeverityBadge, StatusBadge, LoadingSkeleton, EmptyState, JsonViewer } from '@/components';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['', 'open', 'in_progress', 'suppressed', 'closed'];
const PAGE_SIZE = 50;

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [total, setTotal] = useState(0);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAlerts({
        severity: severity || undefined,
        status: status || undefined,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      setAlerts(data);
      setTotal(data.length === PAGE_SIZE ? (page + 2) * PAGE_SIZE : page * PAGE_SIZE + data.length);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [severity, status, page]);
  useEffect(() => {
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [severity, status, page]);

  const filtered = search
    ? alerts.filter(a =>
        a.rule_id.toLowerCase().includes(search.toLowerCase()) ||
        (a.asset_id || '').toLowerCase().includes(search.toLowerCase()) ||
        (a.mitre_technique || '').toLowerCase().includes(search.toLowerCase())
      )
    : alerts;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Alerts</h1>
          <p className="text-sm" style={{ color: '#64748b' }}>
            Detection hits from Sigma rules and ML anomalies
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="tag" style={{ background: '#ff444422', color: '#ff4444', border: '1px solid #ff444444' }}>
            {total} total
          </span>
          <button className="btn btn-ghost text-xs" onClick={load}>↻ Refresh</button>
        </div>
      </div>

      {/* Filters */}
      <div
        className="glass rounded-xl p-4 flex items-center gap-3 flex-wrap"
      >
        <input
          className="input text-sm"
          style={{ maxWidth: '220px' }}
          placeholder="Search rule, asset, MITRE..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
        />
        <select
          className="input text-sm"
          style={{ maxWidth: '150px' }}
          value={severity}
          onChange={e => { setSeverity(e.target.value); setPage(0); }}
        >
          <option value="">All Severities</option>
          {SEVERITIES.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select
          className="input text-sm"
          style={{ maxWidth: '150px' }}
          value={status}
          onChange={e => { setStatus(e.target.value); setPage(0); }}
        >
          <option value="">All Statuses</option>
          {STATUSES.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.replace('_', ' ').charAt(0).toUpperCase() + s.replace('_', ' ').slice(1)}</option>
          ))}
        </select>
        {(severity || status || search) && (
          <button
            className="btn btn-ghost text-xs"
            onClick={() => { setSeverity(''); setStatus(''); setSearch(''); setPage(0); }}
          >
            ✕ Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div className="glass rounded-xl overflow-hidden">
        {error ? (
          <div className="p-8 text-center">
            <div className="text-sm" style={{ color: '#ff4444' }}>⚠ Failed to load alerts: {error}</div>
            <button className="btn btn-ghost mt-4 text-xs" onClick={load}>Retry</button>
          </div>
        ) : loading ? (
          <div className="p-6"><LoadingSkeleton rows={8} cols={6} /></div>
        ) : filtered.length === 0 ? (
          <EmptyState icon="⚡" title="No alerts found" sub="Try adjusting your filters or submit events from the simulator" />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule ID</th>
                  <th>Asset</th>
                  <th>MITRE</th>
                  <th>Confidence</th>
                  <th>Log Type</th>
                  <th>LLM</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(alert => (
                  <>
                    <tr
                      key={alert.id}
                      onClick={() => setExpanded(expanded === alert.id ? null : alert.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td><SeverityBadge severity={alert.severity} /></td>
                      <td>
                        <span className="font-mono text-xs" style={{ color: '#00d4ff' }}>
                          {alert.rule_id.length > 24 ? alert.rule_id.slice(0, 24) + '…' : alert.rule_id}
                        </span>
                      </td>
                      <td>
                        <span className="text-sm">{alert.asset_id || '—'}</span>
                      </td>
                      <td>
                        {alert.mitre_technique ? (
                          <span className="tag font-mono" style={{ background: '#a855f722', color: '#a855f7', border: '1px solid #a855f744' }}>
                            {alert.mitre_technique}
                          </span>
                        ) : <span style={{ color: '#334155' }}>—</span>}
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="confidence-bar">
                            <div
                              className="confidence-fill"
                              style={{
                                width: `${alert.confidence_score * 100}%`,
                                background: alert.confidence_score > 0.8 ? '#ff4444' : alert.confidence_score > 0.6 ? '#ff8800' : '#f59e0b',
                              }}
                            />
                          </div>
                          <span className="font-mono text-xs" style={{ color: '#64748b' }}>
                            {Math.round(alert.confidence_score * 100)}%
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="text-xs font-mono" style={{ color: '#64748b' }}>
                          {alert.source_log_type || '—'}
                        </span>
                      </td>
                      <td>
                        {alert.llm_validated === null ? (
                          <span style={{ color: '#334155' }}>—</span>
                        ) : alert.llm_validated ? (
                          <span title="LLM validated" style={{ color: '#00ff88' }}>✓</span>
                        ) : (
                          <span title="LLM flagged" style={{ color: '#ff4444' }}>✗</span>
                        )}
                      </td>
                      <td><StatusBadge status={alert.status} /></td>
                      <td>
                        <span className="text-xs" style={{ color: '#64748b' }}>{timeAgo(alert.created_at)}</span>
                      </td>
                    </tr>
                    {expanded === alert.id && (
                      <tr key={`${alert.id}-detail`}>
                        <td colSpan={9} style={{ padding: 0 }}>
                          <div
                            className="p-4 space-y-4"
                            style={{ background: '#020817', borderTop: '1px solid #1a2744', borderBottom: '1px solid #1a2744' }}
                          >
                            <div className="grid grid-cols-3 gap-4 text-xs">
                              <div>
                                <div className="font-semibold mb-1" style={{ color: '#64748b' }}>ALERT ID</div>
                                <div className="font-mono" style={{ color: '#00d4ff' }}>{alert.id}</div>
                              </div>
                              <div>
                                <div className="font-semibold mb-1" style={{ color: '#64748b' }}>SOURCE TIMESTAMP</div>
                                <div style={{ color: '#e2e8f0' }}>{alert.source_timestamp || '—'}</div>
                              </div>
                              <div>
                                <div className="font-semibold mb-1" style={{ color: '#64748b' }}>ANOMALY SCORE</div>
                                <div className="font-mono" style={{ color: alert.anomaly_score ? '#ff8800' : '#64748b' }}>
                                  {alert.anomaly_score !== null ? (alert.anomaly_score * 100).toFixed(1) + '%' : '—'}
                                </div>
                              </div>
                            </div>
                            <div>
                              <div className="text-xs font-semibold mb-2" style={{ color: '#64748b' }}>EVIDENCE</div>
                              <JsonViewer data={alert.evidence} />
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            <div
              className="flex items-center justify-between px-6 py-4"
              style={{ borderTop: '1px solid #1a2744' }}
            >
              <span className="text-xs" style={{ color: '#64748b' }}>
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
              </span>
              <div className="flex gap-2">
                <button
                  className="btn btn-ghost text-xs"
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  ← Prev
                </button>
                <button
                  className="btn btn-ghost text-xs"
                  onClick={() => setPage(p => p + 1)}
                  disabled={alerts.length < PAGE_SIZE}
                >
                  Next →
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

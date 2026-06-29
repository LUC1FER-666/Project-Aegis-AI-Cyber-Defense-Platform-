'use client';

import { useEffect, useState } from 'react';
import {
  fetchStats, fetchAlerts, fetchIncidents, fetchTasks, fetchAgentStats,
  approveTask, rejectTask,
  type DetectionStats, type Alert, type Incident, type AgentTask, type AgentStats,
  timeAgo, severityColor, statusColor,
} from '@/lib/api';
import { SeverityBadge, StatusBadge, MetricCard, CardSkeleton, EmptyState } from '@/components';

export default function DashboardPage() {
  const [stats, setStats] = useState<DetectionStats | null>(null);
  const [agentStats, setAgentStats] = useState<AgentStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [pendingTasks, setPendingTasks] = useState<AgentTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [approving, setApproving] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const load = async () => {
    try {
      const [s, as, al, inc, tasks] = await Promise.allSettled([
        fetchStats(),
        fetchAgentStats(),
        fetchAlerts({ limit: 10 }),
        fetchIncidents({ limit: 5 }),
        fetchTasks({ status: 'pending_approval', limit: 10 }),
      ]);
      if (s.status === 'fulfilled') setStats(s.value);
      if (as.status === 'fulfilled') setAgentStats(as.value);
      if (al.status === 'fulfilled') setAlerts(al.value);
      if (inc.status === 'fulfilled') setIncidents(inc.value);
      if (tasks.status === 'fulfilled') setPendingTasks(tasks.value?.tasks ?? tasks.value);
      setLastUpdated(new Date());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleApprove = async (taskId: string) => {
    setApproving(taskId);
    try {
      await approveTask(taskId, { notes: 'Approved from dashboard', approved_by: 'SOC Analyst' });
      await load();
    } finally {
      setApproving(null);
    }
  };

  const handleReject = async (taskId: string) => {
    setApproving(taskId);
    try {
      await rejectTask(taskId, { notes: 'Rejected from dashboard' });
      await load();
    } finally {
      setApproving(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">SOC Dashboard</h1>
          <p className="text-sm" style={{ color: '#64748b' }}>
            Live threat overview · updates every 10s
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs" style={{ color: '#64748b' }}>
          <span className="status-dot live" />
          <span>Last updated {lastUpdated.toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-4 gap-4">
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => <CardSkeleton key={i} />)
        ) : (
          <>
            <MetricCard
              label="Total Alerts"
              value={stats?.total_alerts ?? 0}
              sub={`${stats?.alerts_last_hour ?? 0} in last hour`}
              color="#ff4444"
              icon="⚡"
              glow={(stats?.total_alerts ?? 0) > 0}
            />
            <MetricCard
              label="Open Incidents"
              value={stats?.open_incidents ?? 0}
              sub={`${stats?.total_incidents ?? 0} total`}
              color="#ff8800"
              icon="🔴"
              glow={(stats?.open_incidents ?? 0) > 0}
            />
            <MetricCard
              label="Pending Approvals"
              value={agentStats?.pending_approval_count ?? 0}
              sub="agent tasks awaiting review"
              color="#f59e0b"
              icon="◎"
              glow={(agentStats?.pending_approval_count ?? 0) > 0}
            />
            <MetricCard
              label="Rules Loaded"
              value={stats?.rules_loaded ?? 0}
              sub={stats?.ml_model_trained ? 'ML trained' : 'ML not trained'}
              color="#00d4ff"
              icon="◈"
            />
          </>
        )}
      </div>

      {/* Alert Severity Breakdown */}
      <div className="glass rounded-xl p-6">
        <h2 className="text-sm font-semibold uppercase tracking-widest mb-5" style={{ color: '#64748b' }}>
          Alert Severity Breakdown
        </h2>
        {loading ? (
          <div className="space-y-3">
            {['critical', 'high', 'medium', 'low'].map(s => (
              <div key={s} className="skeleton h-6 rounded" />
            ))}
          </div>
        ) : (
          <div className="space-y-3">
            {[
              { label: 'Critical', key: 'critical', color: '#ff4444' },
              { label: 'High', key: 'high', color: '#ff8800' },
              { label: 'Medium', key: 'medium', color: '#f59e0b' },
              { label: 'Low', key: 'low', color: '#00ff88' },
            ].map(({ label, key, color }) => {
              const count = alerts.filter(a => a.severity === key).length;
              const total = alerts.length || 1;
              const pct = Math.round((count / total) * 100);
              return (
                <div key={key} className="flex items-center gap-4">
                  <span className="text-xs font-mono w-16" style={{ color }}>{label}</span>
                  <div className="flex-1 h-5 rounded overflow-hidden" style={{ background: '#0a0f1e' }}>
                    <div
                      className="h-full rounded transition-all duration-500 flex items-center pl-2"
                      style={{
                        width: `${pct}%`,
                        minWidth: count > 0 ? '32px' : '0',
                        background: `linear-gradient(90deg, ${color}88, ${color}44)`,
                        boxShadow: count > 0 ? `0 0 10px ${color}44` : 'none',
                      }}
                    >
                      {count > 0 && <span className="text-xs font-bold" style={{ color }}>{count}</span>}
                    </div>
                  </div>
                  <span className="text-xs font-mono w-8 text-right" style={{ color: '#64748b' }}>{count}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Pending Approvals */}
        <div className="glass rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid #1a2744' }}>
            <h2 className="text-sm font-semibold text-white">Pending Approvals</h2>
            {pendingTasks.length > 0 && (
              <span className="tag" style={{ background: '#f59e0b22', color: '#f59e0b', border: '1px solid #f59e0b44' }}>
                {pendingTasks.length}
              </span>
            )}
          </div>
          <div className="p-4">
            {loading ? (
              <div className="space-y-3">
                {Array.from({ length: 2 }).map((_, i) => <div key={i} className="skeleton h-16 rounded-lg" />)}
              </div>
            ) : pendingTasks.length === 0 ? (
              <EmptyState icon="✓" title="No tasks awaiting approval" />
            ) : (
              <div className="space-y-3">
                {pendingTasks.map(task => (
                  <div
                    key={task.id}
                    className="rounded-lg p-4 space-y-3"
                    style={{ background: '#0a0f1e', border: '1px solid #1a2744' }}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-white truncate">{task.incident_title}</div>
                        <div className="text-xs mt-0.5" style={{ color: '#64748b' }}>
                          {task.selected_playbook?.replace(/_/g, ' ')} · {timeAgo(task.created_at)}
                        </div>
                      </div>
                      <SeverityBadge severity={task.severity} />
                    </div>
                    {task.triage && (
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded overflow-hidden" style={{ background: '#1a2744' }}>
                          <div
                            className="h-full rounded"
                            style={{
                              width: `${task.triage.urgency_score * 100}%`,
                              background: task.triage.urgency_score > 0.8 ? '#ff4444' : task.triage.urgency_score > 0.5 ? '#ff8800' : '#f59e0b',
                            }}
                          />
                        </div>
                        <span className="text-xs font-mono" style={{ color: '#64748b' }}>
                          {Math.round(task.triage.urgency_score * 100)}% urgency
                        </span>
                      </div>
                    )}
                    <div className="flex gap-2">
                      <button
                        className="btn btn-success flex-1 justify-center text-xs py-1.5"
                        onClick={() => handleApprove(task.id)}
                        disabled={approving === task.id}
                      >
                        {approving === task.id ? '...' : '✓ Approve'}
                      </button>
                      <button
                        className="btn btn-danger flex-1 justify-center text-xs py-1.5"
                        onClick={() => handleReject(task.id)}
                        disabled={approving === task.id}
                      >
                        ✕ Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="glass rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid #1a2744' }}>
            <h2 className="text-sm font-semibold text-white">Recent Incidents</h2>
            <a href="/incidents" className="text-xs" style={{ color: '#00d4ff' }}>View all →</a>
          </div>
          <div>
            {loading ? (
              <div className="p-4 space-y-2">
                {Array.from({ length: 3 }).map((_, i) => <div key={i} className="skeleton h-14 rounded" />)}
              </div>
            ) : incidents.length === 0 ? (
              <EmptyState icon="🛡" title="No incidents yet" />
            ) : (
              incidents.map(inc => (
                <div
                  key={inc.id}
                  className="px-6 py-4 flex items-center gap-4 transition-colors"
                  style={{ borderBottom: '1px solid rgba(26,39,68,0.5)', cursor: 'pointer' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(17,29,53,0.5)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <div
                    className="w-1 self-stretch rounded-full flex-shrink-0"
                    style={{ background: severityColor(inc.severity) }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-white truncate">{inc.title}</div>
                    <div className="text-xs mt-0.5" style={{ color: '#64748b' }}>
                      {inc.alert_count} alerts · {inc.affected_assets.slice(0, 2).join(', ')}
                      {inc.affected_assets.length > 2 && ` +${inc.affected_assets.length - 2}`}
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <StatusBadge status={inc.status} />
                    <div className="text-xs mt-1" style={{ color: '#64748b' }}>{timeAgo(inc.created_at)}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid #1a2744' }}>
          <h2 className="text-sm font-semibold text-white">Recent Alerts</h2>
          <a href="/alerts" className="text-xs" style={{ color: '#00d4ff' }}>View all →</a>
        </div>
        {loading ? (
          <div className="p-6"><div className="skeleton h-32 rounded" /></div>
        ) : alerts.length === 0 ? (
          <EmptyState icon="⚡" title="No alerts yet — submit events from the simulator" />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Asset</th>
                <th>MITRE</th>
                <th>Confidence</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => (
                <tr key={alert.id}>
                  <td><SeverityBadge severity={alert.severity} /></td>
                  <td>
                    <span className="font-mono text-xs" style={{ color: '#00d4ff' }}>
                      {alert.rule_id.slice(0, 20)}...
                    </span>
                  </td>
                  <td>
                    <span style={{ color: '#e2e8f0' }}>{alert.asset_id || '—'}</span>
                  </td>
                  <td>
                    {alert.mitre_technique ? (
                      <span className="tag font-mono" style={{ background: '#a855f722', color: '#a855f7', border: '1px solid #a855f744' }}>
                        {alert.mitre_technique}
                      </span>
                    ) : '—'}
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
                      <span className="text-xs font-mono" style={{ color: '#64748b' }}>
                        {Math.round(alert.confidence_score * 100)}%
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className="text-xs" style={{ color: '#64748b' }}>{timeAgo(alert.created_at)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

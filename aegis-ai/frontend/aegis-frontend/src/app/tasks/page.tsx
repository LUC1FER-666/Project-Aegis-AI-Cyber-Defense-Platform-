'use client';

import { useEffect, useState } from 'react';
import {
  fetchTasks, fetchTask, fetchTaskActions,
  approveTask, rejectTask,
  type AgentTask, type ActionLog,
  timeAgo, severityColor, statusColor,
} from '@/lib/api';
import { SeverityBadge, StatusBadge, EmptyState, LoadingSkeleton, JsonViewer } from '@/components';

const STATUS_TABS = [
  { label: 'All', value: '' },
  { label: 'Pending', value: 'pending_approval' },
  { label: 'Executing', value: 'executing' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' },
];

const ACTION_ICONS: Record<string, string> = {
  block_ip: '🚫',
  isolate_host: '🔒',
  kill_process: '☠',
  collect_logs: '📋',
  notify_soc: '📢',
  force_password_reset: '🔑',
  escalate_to_analyst: '👤',
  enrich_asset: '🔍',
};

export default function TasksPage() {
  const [tasks, setTasks] = useState<AgentTask[]>([]);
  const [selected, setSelected] = useState<AgentTask | null>(null);
  const [actions, setActions] = useState<ActionLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [statusTab, setStatusTab] = useState('');
  const [approving, setApproving] = useState(false);
  const [approvalNotes, setApprovalNotes] = useState('');
  const [approvedBy, setApprovedBy] = useState('SOC Analyst');
  const [expandedAction, setExpandedAction] = useState<string | null>(null);

  const loadTasks = async () => {
    setLoading(true);
    try {
      const data = await fetchTasks({ status: statusTab || undefined, limit: 100 });
      setTasks(data);
    } finally {
      setLoading(false);
    }
  };

  const loadDetail = async (taskId: string) => {
    setDetailLoading(true);
    try {
      const [task, acts] = await Promise.all([
        fetchTask(taskId),
        fetchTaskActions(taskId).catch(() => []),
      ]);
      setSelected(task);
      setActions(acts);
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => { loadTasks(); }, [statusTab]);
  useEffect(() => {
    const interval = setInterval(() => {
      loadTasks();
      if (selected) loadDetail(selected.id);
    }, 10000);
    return () => clearInterval(interval);
  }, [statusTab, selected?.id]);

  const handleApprove = async () => {
    if (!selected) return;
    setApproving(true);
    try {
      await approveTask(selected.id, { notes: approvalNotes, approved_by: approvedBy });
      await Promise.all([loadTasks(), loadDetail(selected.id)]);
      setApprovalNotes('');
    } finally {
      setApproving(false);
    }
  };

  const handleReject = async () => {
    if (!selected) return;
    setApproving(true);
    try {
      await rejectTask(selected.id, { notes: approvalNotes || 'Rejected' });
      await Promise.all([loadTasks(), loadDetail(selected.id)]);
      setApprovalNotes('');
    } finally {
      setApproving(false);
    }
  };

  const urgencyGradient = (score: number) => {
    if (score > 0.8) return '#ff4444';
    if (score > 0.6) return '#ff8800';
    if (score > 0.4) return '#f59e0b';
    return '#00ff88';
  };

  return (
    <div className="flex gap-6" style={{ minHeight: 'calc(100vh - 64px)' }}>
      {/* Task List */}
      <div className="flex-shrink-0 space-y-4" style={{ width: '340px' }}>
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Agent Tasks</h1>
          <p className="text-sm" style={{ color: '#64748b' }}>Autonomous response pipeline</p>
        </div>

        {/* Status tabs */}
        <div
          className="flex gap-1 p-1 rounded-xl"
          style={{ background: '#0a0f1e', border: '1px solid #1a2744' }}
        >
          {STATUS_TABS.map(tab => (
            <button
              key={tab.value}
              onClick={() => { setStatusTab(tab.value); setSelected(null); }}
              className="flex-1 py-1.5 px-2 rounded-lg text-xs font-medium transition-all duration-200"
              style={{
                background: statusTab === tab.value ? '#1a2744' : 'transparent',
                color: statusTab === tab.value ? '#e2e8f0' : '#64748b',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Task list */}
        <div className="space-y-2 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 200px)' }}>
          {loading ? (
            Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="glass rounded-xl p-4">
                <LoadingSkeleton rows={3} cols={2} />
              </div>
            ))
          ) : tasks.length === 0 ? (
            <div className="glass rounded-xl">
              <EmptyState icon="◎" title="No tasks" sub="Submit incidents to generate tasks" />
            </div>
          ) : (
            tasks.map(task => {
              const isSelected = selected?.id === task.id;
              const color = statusColor(task.status);
              return (
                <div
                  key={task.id}
                  className="glass rounded-xl p-4 cursor-pointer transition-all duration-200"
                  style={{
                    borderColor: isSelected ? '#00d4ff44' : '#1a2744',
                    background: isSelected ? 'rgba(0,212,255,0.05)' : undefined,
                  }}
                  onClick={() => loadDetail(task.id)}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="text-xs font-medium text-white leading-snug flex-1 pr-2 line-clamp-2">
                      {task.incident_title}
                    </div>
                    <SeverityBadge severity={task.severity} />
                  </div>
                  <div className="flex items-center justify-between mb-2">
                    <StatusBadge status={task.status} />
                    <span className="text-xs" style={{ color: '#64748b' }}>{timeAgo(task.created_at)}</span>
                  </div>
                  {task.triage && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs" style={{ color: '#64748b' }}>Urgency</span>
                        <span className="text-xs font-mono" style={{ color: urgencyGradient(task.triage.urgency_score) }}>
                          {Math.round(task.triage.urgency_score * 100)}%
                        </span>
                      </div>
                      <div className="h-1 rounded-full overflow-hidden" style={{ background: '#1a2744' }}>
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${task.triage.urgency_score * 100}%`,
                            background: urgencyGradient(task.triage.urgency_score),
                            boxShadow: `0 0 6px ${urgencyGradient(task.triage.urgency_score)}88`,
                          }}
                        />
                      </div>
                    </div>
                  )}
                  {task.selected_playbook && (
                    <div className="text-xs mt-2 font-mono" style={{ color: '#64748b' }}>
                      ▶ {task.selected_playbook.replace(/_/g, ' ')}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Detail panel */}
      <div className="flex-1 min-w-0">
        {!selected ? (
          <div className="glass rounded-xl h-full flex items-center justify-center">
            <EmptyState icon="◎" title="Select a task to view details" />
          </div>
        ) : detailLoading ? (
          <div className="glass rounded-xl p-8">
            <LoadingSkeleton rows={8} cols={3} />
          </div>
        ) : (
          <div className="space-y-4">
            {/* Task header */}
            <div className="glass rounded-xl p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1 min-w-0 pr-4">
                  <h2 className="text-lg font-semibold text-white mb-1">{selected.incident_title}</h2>
                  <div className="font-mono text-xs" style={{ color: '#334155' }}>{selected.id}</div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <SeverityBadge severity={selected.severity} />
                  <StatusBadge status={selected.status} />
                </div>
              </div>
              {selected.selected_playbook && (
                <div className="flex items-center gap-2">
                  <span className="text-xs" style={{ color: '#64748b' }}>Playbook:</span>
                  <span
                    className="tag font-mono"
                    style={{ background: '#00d4ff11', color: '#00d4ff', border: '1px solid #00d4ff22' }}
                  >
                    {selected.selected_playbook.replace(/_/g, ' ')}
                  </span>
                </div>
              )}
            </div>

            {/* Triage */}
            {selected.triage && (
              <div className="glass rounded-xl p-5">
                <h3 className="text-xs font-semibold uppercase tracking-widest mb-4" style={{ color: '#64748b' }}>
                  AI Triage Assessment
                </h3>
                <div className="grid grid-cols-3 gap-4 mb-4">
                  {/* Urgency gauge */}
                  <div className="text-center">
                    <div
                      className="w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-2 relative"
                      style={{
                        background: `conic-gradient(${urgencyGradient(selected.triage.urgency_score)} ${selected.triage.urgency_score * 360}deg, #1a2744 0deg)`,
                        padding: '3px',
                      }}
                    >
                      <div
                        className="w-full h-full rounded-full flex items-center justify-center"
                        style={{ background: '#0d1528' }}
                      >
                        <span className="text-lg font-bold" style={{ color: urgencyGradient(selected.triage.urgency_score) }}>
                          {Math.round(selected.triage.urgency_score * 100)}
                        </span>
                      </div>
                    </div>
                    <div className="text-xs" style={{ color: '#64748b' }}>Urgency Score</div>
                  </div>
                  <div>
                    <div className="text-xs mb-1" style={{ color: '#64748b' }}>Attack Stage</div>
                    <div
                      className="tag mt-1"
                      style={{ background: '#a855f722', color: '#a855f7', border: '1px solid #a855f744' }}
                    >
                      {selected.triage.attack_stage.replace(/_/g, ' ')}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs mb-1" style={{ color: '#64748b' }}>Response Tier</div>
                    <div
                      className="tag mt-1"
                      style={{
                        background: selected.triage.recommended_response_tier === 'automated' ? '#00ff8822' : '#f59e0b22',
                        color: selected.triage.recommended_response_tier === 'automated' ? '#00ff88' : '#f59e0b',
                        border: `1px solid ${selected.triage.recommended_response_tier === 'automated' ? '#00ff8844' : '#f59e0b44'}`,
                      }}
                    >
                      {selected.triage.recommended_response_tier}
                    </div>
                  </div>
                </div>
                <div className="text-xs leading-relaxed mb-3" style={{ color: '#94a3b8' }}>
                  {selected.triage.summary}
                </div>
                {selected.triage.key_indicators.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {selected.triage.key_indicators.map((ind, i) => (
                      <span key={i} className="tag" style={{ background: '#1a2744', color: '#64748b', border: '1px solid #243354' }}>
                        {ind}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Playbook Steps */}
            {selected.playbook_steps && selected.playbook_steps.length > 0 && (
              <div className="glass rounded-xl p-5">
                <h3 className="text-xs font-semibold uppercase tracking-widest mb-4" style={{ color: '#64748b' }}>
                  Playbook Steps
                </h3>
                <div className="space-y-2">
                  {selected.playbook_steps.map((step, i) => {
                    const result = selected.actions_results?.find(r => r.action_type === step.action_type);
                    const done = !!result;
                    const failed = result?.status === 'failed';
                    return (
                      <div
                        key={i}
                        className="flex items-center gap-3 p-3 rounded-lg"
                        style={{ background: '#020817', border: `1px solid ${done ? (failed ? '#ff444422' : '#00ff8822') : '#1a2744'}` }}
                      >
                        <div
                          className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
                          style={{
                            background: done ? (failed ? '#ff444422' : '#00ff8822') : '#1a2744',
                            color: done ? (failed ? '#ff4444' : '#00ff88') : '#64748b',
                          }}
                        >
                          {done ? (failed ? '✗' : '✓') : i + 1}
                        </div>
                        <span className="text-lg">{ACTION_ICONS[step.action_type] || '▶'}</span>
                        <div className="flex-1">
                          <div className="text-sm font-medium" style={{ color: done ? '#e2e8f0' : '#64748b' }}>
                            {step.action_type.replace(/_/g, ' ')}
                          </div>
                          <div className="text-xs" style={{ color: '#334155' }}>{step.target}</div>
                        </div>
                        {result && (
                          <span className="text-xs font-mono" style={{ color: '#334155' }}>
                            {result.duration_ms}ms
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Action Results */}
            {actions.length > 0 && (
              <div className="glass rounded-xl p-5">
                <h3 className="text-xs font-semibold uppercase tracking-widest mb-4" style={{ color: '#64748b' }}>
                  Execution Results
                </h3>
                <div className="space-y-2">
                  {actions.map(action => (
                    <div key={action.id}>
                      <div
                        className="flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors"
                        style={{ background: '#020817', border: '1px solid #1a2744' }}
                        onClick={() => setExpandedAction(expandedAction === action.id ? null : action.id)}
                      >
                        <span className="text-lg">{ACTION_ICONS[action.action_type] || '▶'}</span>
                        <div className="flex-1">
                          <div className="text-sm font-medium text-white">{action.action_type.replace(/_/g, ' ')}</div>
                          <div className="text-xs" style={{ color: '#64748b' }}>{action.target}</div>
                        </div>
                        <div className="flex items-center gap-3 flex-shrink-0">
                          <span className="text-xs font-mono" style={{ color: '#334155' }}>{action.duration_ms}ms</span>
                          <span
                            className="tag text-xs"
                            style={{
                              color: action.status === 'success' ? '#00ff88' : '#ff4444',
                              background: action.status === 'success' ? '#00ff8822' : '#ff444422',
                              border: `1px solid ${action.status === 'success' ? '#00ff8844' : '#ff444444'}`,
                            }}
                          >
                            {action.status}
                          </span>
                          <span style={{ color: '#334155', fontSize: '10px' }}>
                            {expandedAction === action.id ? '▲' : '▼'}
                          </span>
                        </div>
                      </div>
                      {expandedAction === action.id && (
                        <div className="mt-1 rounded-lg overflow-hidden" style={{ border: '1px solid #1a2744' }}>
                          <JsonViewer data={action.result_data} />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Approval panel */}
            {selected.status === 'pending_approval' && (
              <div
                className="glass rounded-xl p-5"
                style={{ borderColor: '#f59e0b44', boxShadow: '0 0 20px rgba(245,158,11,0.1)' }}
              >
                <h3 className="text-xs font-semibold uppercase tracking-widest mb-4" style={{ color: '#f59e0b' }}>
                  ⚠ Awaiting Approval
                </h3>
                <div className="space-y-3">
                  <div>
                    <label className="text-xs mb-1.5 block" style={{ color: '#64748b' }}>Approved By</label>
                    <input
                      className="input text-sm"
                      value={approvedBy}
                      onChange={e => setApprovedBy(e.target.value)}
                      placeholder="Your name"
                    />
                  </div>
                  <div>
                    <label className="text-xs mb-1.5 block" style={{ color: '#64748b' }}>Notes (optional)</label>
                    <textarea
                      className="input text-sm resize-none"
                      rows={2}
                      value={approvalNotes}
                      onChange={e => setApprovalNotes(e.target.value)}
                      placeholder="Add approval notes..."
                    />
                  </div>
                  <div className="flex gap-3">
                    <button
                      className="btn btn-success flex-1 justify-center"
                      onClick={handleApprove}
                      disabled={approving}
                    >
                      {approving ? '...' : '✓ Approve & Execute'}
                    </button>
                    <button
                      className="btn btn-danger flex-1 justify-center"
                      onClick={handleReject}
                      disabled={approving}
                    >
                      ✕ Reject
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Approval info */}
            {selected.approved_by && (
              <div className="glass rounded-xl p-4">
                <div className="text-xs" style={{ color: '#64748b' }}>
                  {selected.status === 'rejected' ? '✗ Rejected' : '✓ Approved'} by{' '}
                  <span className="text-white">{selected.approved_by}</span>
                  {selected.approved_at && ` · ${timeAgo(selected.approved_at)}`}
                </div>
                {selected.approval_notes && (
                  <div className="text-xs mt-1" style={{ color: '#64748b' }}>"{selected.approval_notes}"</div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

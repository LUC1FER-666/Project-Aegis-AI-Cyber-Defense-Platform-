'use client';

import { useState } from 'react';
import { analyzeEvent, type AnalyzeResult, timeAgo } from '@/lib/api';
import { SeverityBadge, JsonViewer } from '@/components';

interface HistoryEntry {
  id: string;
  template: string;
  timestamp: string;
  result: AnalyzeResult;
  event: Record<string, unknown>;
}

const TEMPLATES: Record<string, { label: string; icon: string; color: string; event: Record<string, unknown> }> = {
  powershell: {
    label: 'PowerShell Attack',
    icon: '⚡',
    color: '#ff4444',
    event: {
      event_type: 'process',
      log_type: 'process',
      hostname: 'WORKSTATION-01',
      asset_id: 'asset-ws01',
      timestamp: new Date().toISOString(),
      process_name: 'powershell.exe',
      CommandLine: 'powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==',
      user: 'WORKSTATION-01\\user',
      parent_process: 'explorer.exe',
    },
  },
  brute_force: {
    label: 'Brute Force Auth',
    icon: '🔑',
    color: '#ff8800',
    event: {
      log_type: 'auth',
      hostname: 'DC-01',
      asset_id: 'asset-dc01',
      timestamp: new Date().toISOString(),
      status: 'failure',
      user: 'administrator',
      src_ip: '203.0.113.45',
      dst_ip: '10.0.0.1',
      auth_type: 'ntlm',
      failure_reason: 'Invalid credentials',
    },
  },
  dns_tunnel: {
    label: 'DNS Tunneling',
    icon: '🌐',
    color: '#a855f7',
    event: {
      log_type: 'dns',
      hostname: 'WORKSTATION-03',
      asset_id: 'asset-ws03',
      timestamp: new Date().toISOString(),
      query: 'aabbccddeeff00112233445566778899aabbccdd112233.exfil-c2.evil-domain.com',
      record_type: 'TXT',
      src_ip: '10.0.0.15',
      response_code: 'NOERROR',
    },
  },
  c2_connection: {
    label: 'C2 Connection',
    icon: '📡',
    color: '#ff4444',
    event: {
      log_type: 'netflow',
      hostname: 'SERVER-02',
      asset_id: 'asset-srv02',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.0.20',
      dst_ip: '198.51.100.99',
      dst_port: 4444,
      src_port: 54321,
      protocol: 'tcp',
      bytes_out: 24576,
      bytes_in: 8192,
      duration: 120,
    },
  },
  lateral_move: {
    label: 'Lateral Movement',
    icon: '↔',
    color: '#f59e0b',
    event: {
      log_type: 'auth',
      hostname: 'FILESERVER-01',
      asset_id: 'asset-fs01',
      timestamp: new Date().toISOString(),
      status: 'success',
      user: 'DOMAIN\\svc_account',
      src_ip: '10.0.0.45',
      dst_ip: '10.0.0.100',
      auth_type: 'kerberos',
      event_id: 4624,
      logon_type: 3,
    },
  },
};

export default function SimulatorPage() {
  const [activeTemplate, setActiveTemplate] = useState('powershell');
  const [payload, setPayload] = useState(JSON.stringify(TEMPLATES.powershell.event, null, 2));
  const [submitting, setSubmitting] = useState(false);
  const [lastResult, setLastResult] = useState<AnalyzeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const selectTemplate = (key: string) => {
    setActiveTemplate(key);
    const tpl = TEMPLATES[key];
    setPayload(JSON.stringify({ ...tpl.event, timestamp: new Date().toISOString() }, null, 2));
    setLastResult(null);
    setError(null);
  };

  const handleSubmit = async () => {
    setSubmitting(true);
    setError(null);
    setLastResult(null);
    try {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(payload);
      } catch {
        setError('Invalid JSON — check your payload');
        return;
      }

      const result = await analyzeEvent(parsed);
      setLastResult(result);
      setHistory(prev => [{
        id: Math.random().toString(36).slice(2),
        template: TEMPLATES[activeTemplate]?.label || activeTemplate,
        timestamp: new Date().toISOString(),
        result,
        event: parsed,
      }, ...prev.slice(0, 9)]);
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const tpl = TEMPLATES[activeTemplate];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white mb-1">Event Simulator</h1>
        <p className="text-sm" style={{ color: '#64748b' }}>
          Submit synthetic telemetry to the detection engine and watch alerts fire in real time
        </p>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Left: editor */}
        <div className="col-span-2 space-y-4">
          {/* Attack templates */}
          <div className="glass rounded-xl p-4">
            <div className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: '#64748b' }}>
              Attack Templates
            </div>
            <div className="flex gap-2 flex-wrap">
              {Object.entries(TEMPLATES).map(([key, { label, icon, color }]) => (
                <button
                  key={key}
                  className="btn text-xs py-2 px-3"
                  onClick={() => selectTemplate(key)}
                  style={{
                    background: activeTemplate === key ? color + '22' : 'transparent',
                    borderColor: activeTemplate === key ? color + '66' : '#1a2744',
                    color: activeTemplate === key ? color : '#64748b',
                    boxShadow: activeTemplate === key ? `0 0 12px ${color}33` : 'none',
                  }}
                >
                  <span>{icon}</span>
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* JSON Editor */}
          <div className="glass rounded-xl overflow-hidden">
            <div
              className="flex items-center justify-between px-4 py-3"
              style={{ borderBottom: '1px solid #1a2744', background: '#020817' }}
            >
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium" style={{ color: tpl?.color || '#00d4ff' }}>
                  {tpl?.icon} {tpl?.label}
                </span>
                <span className="tag text-xs" style={{ background: '#1a2744', color: '#64748b', border: '1px solid #243354' }}>
                  JSON
                </span>
              </div>
              <button
                className="btn btn-ghost text-xs py-1"
                onClick={() => selectTemplate(activeTemplate)}
              >
                ↺ Reset
              </button>
            </div>
            <textarea
              className="font-mono text-xs w-full p-4 resize-none outline-none leading-6"
              style={{
                background: '#020817',
                color: '#e2e8f0',
                minHeight: '320px',
                border: 'none',
              }}
              value={payload}
              onChange={e => setPayload(e.target.value)}
              spellCheck={false}
            />
            <div
              className="flex items-center justify-between px-4 py-3"
              style={{ borderTop: '1px solid #1a2744', background: '#020817' }}
            >
              <span className="text-xs" style={{ color: '#334155' }}>
                {payload.split('\n').length} lines · {payload.length} chars
              </span>
              <button
                className="btn btn-primary"
                onClick={handleSubmit}
                disabled={submitting}
                style={{ minWidth: '180px', justifyContent: 'center' }}
              >
                {submitting ? (
                  <span className="flex items-center gap-2">
                    <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Analyzing...
                  </span>
                ) : (
                  '▶ Submit to Detection Engine'
                )}
              </button>
            </div>
          </div>

          {/* Result */}
          {error && (
            <div
              className="glass rounded-xl p-4"
              style={{ borderColor: '#ff444444', background: '#ff444408' }}
            >
              <div className="text-sm font-semibold mb-1" style={{ color: '#ff4444' }}>⚠ Error</div>
              <div className="text-xs font-mono" style={{ color: '#ff8888' }}>{error}</div>
            </div>
          )}

          {lastResult && (
            <div
              className="glass rounded-xl overflow-hidden"
              style={{
                borderColor: lastResult.alerts_created > 0 ? '#ff444444' : '#00ff8844',
                boxShadow: lastResult.alerts_created > 0 ? '0 0 20px rgba(255,68,68,0.1)' : '0 0 20px rgba(0,255,136,0.1)',
              }}
            >
              <div
                className="px-5 py-3 flex items-center gap-3"
                style={{
                  borderBottom: '1px solid #1a2744',
                  background: lastResult.alerts_created > 0 ? '#ff444408' : '#00ff8808',
                }}
              >
                <span className="text-xl">{lastResult.alerts_created > 0 ? '🚨' : '✓'}</span>
                <div>
                  <div className="text-sm font-semibold" style={{ color: lastResult.alerts_created > 0 ? '#ff4444' : '#00ff88' }}>
                    {lastResult.alerts_created > 0
                      ? `${lastResult.alerts_created} Alert${lastResult.alerts_created !== 1 ? 's' : ''} Created`
                      : 'No Alerts — Event appears benign'}
                  </div>
                  <div className="text-xs" style={{ color: '#64748b' }}>
                    Detection engine processed the event
                  </div>
                </div>
              </div>
              {lastResult.alerts.length > 0 && (
                <div className="p-4 space-y-3">
                  {lastResult.alerts.map((alert, i) => (
                    <div
                      key={i}
                      className="rounded-lg p-4"
                      style={{ background: '#020817', border: '1px solid #1a2744' }}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <div className="font-mono text-xs mb-1" style={{ color: '#00d4ff' }}>{alert.rule_id}</div>
                          {alert.mitre_technique && (
                            <span className="tag font-mono" style={{ background: '#a855f722', color: '#a855f7', border: '1px solid #a855f744' }}>
                              {alert.mitre_technique}
                            </span>
                          )}
                        </div>
                        <SeverityBadge severity={alert.severity} />
                      </div>
                      <div className="flex items-center gap-4 text-xs">
                        <div>
                          <span style={{ color: '#64748b' }}>Confidence: </span>
                          <span className="font-mono font-bold" style={{ color: '#e2e8f0' }}>
                            {Math.round(alert.confidence_score * 100)}%
                          </span>
                        </div>
                        <div>
                          <span style={{ color: '#64748b' }}>Asset: </span>
                          <span style={{ color: '#e2e8f0' }}>{alert.asset_id || '—'}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right: history */}
        <div className="space-y-4">
          <div className="glass rounded-xl overflow-hidden">
            <div className="px-4 py-3" style={{ borderBottom: '1px solid #1a2744' }}>
              <div className="text-xs font-semibold uppercase tracking-widest" style={{ color: '#64748b' }}>
                Submission History
              </div>
            </div>
            <div className="overflow-y-auto" style={{ maxHeight: '600px' }}>
              {history.length === 0 ? (
                <div className="p-8 text-center">
                  <div className="text-3xl mb-2 opacity-20">▶</div>
                  <div className="text-xs" style={{ color: '#64748b' }}>No events submitted yet</div>
                </div>
              ) : (
                history.map(entry => (
                  <div
                    key={entry.id}
                    className="px-4 py-3 transition-colors"
                    style={{ borderBottom: '1px solid rgba(26,39,68,0.5)', cursor: 'pointer' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(17,29,53,0.5)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  >
                    <div className="flex items-start justify-between mb-1">
                      <span className="text-xs font-medium text-white">{entry.template}</span>
                      <span
                        className="text-xs font-bold font-mono"
                        style={{ color: entry.result.alerts_created > 0 ? '#ff4444' : '#00ff88' }}
                      >
                        {entry.result.alerts_created > 0 ? `+${entry.result.alerts_created}` : '✓'}
                      </span>
                    </div>
                    <div className="text-xs" style={{ color: '#334155' }}>{timeAgo(entry.timestamp)}</div>
                    {entry.result.alerts.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {entry.result.alerts.map((a, i) => (
                          <SeverityBadge key={i} severity={a.severity} />
                        ))}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Tips */}
          <div className="glass rounded-xl p-4">
            <div className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: '#64748b' }}>
              Demo Tips
            </div>
            <div className="space-y-2 text-xs" style={{ color: '#64748b' }}>
              {[
                'Submit PowerShell Attack to trigger T1059.001',
                'Submit Brute Force twice to create an incident',
                'Watch the Dashboard update in real time',
                'Check Agent Tasks for automated responses',
                'Edit the JSON to test custom events',
              ].map((tip, i) => (
                <div key={i} className="flex gap-2">
                  <span style={{ color: '#334155' }}>{i + 1}.</span>
                  <span>{tip}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

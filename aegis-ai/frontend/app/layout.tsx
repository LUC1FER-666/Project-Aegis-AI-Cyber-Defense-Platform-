'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import { fetchStats, fetchAgentStats } from '@/lib/api';
import './globals.css';

interface NavCounts {
  alerts: number;
  incidents: number;
  pending: number;
}

function NavItem({
  href,
  icon,
  label,
  badge,
  badgeColor = '#ff4444',
  active,
}: {
  href: string;
  icon: string;
  label: string;
  badge?: number;
  badgeColor?: string;
  active: boolean;
}) {
  return (
    <Link href={href}>
      <div
        className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-all duration-200 group relative"
        style={{
          background: active ? 'rgba(0, 212, 255, 0.08)' : 'transparent',
          borderLeft: active ? '2px solid #00d4ff' : '2px solid transparent',
          color: active ? '#00d4ff' : '#64748b',
        }}
      >
        <span className="text-base w-5 text-center">{icon}</span>
        <span className="text-sm font-medium flex-1">{label}</span>
        {badge !== undefined && badge > 0 && (
          <span
            className="text-xs font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center"
            style={{ background: badgeColor + '22', color: badgeColor, border: `1px solid ${badgeColor}44` }}
          >
            {badge > 99 ? '99+' : badge}
          </span>
        )}
        {!active && (
          <div
            className="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
            style={{ background: 'rgba(0, 212, 255, 0.04)' }}
          />
        )}
      </div>
    </Link>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [counts, setCounts] = useState<NavCounts>({ alerts: 0, incidents: 0, pending: 0 });
  const [systemStatus, setSystemStatus] = useState<'online' | 'degraded' | 'offline'>('offline');

  useEffect(() => {
    const load = async () => {
      try {
        const [det, agent] = await Promise.allSettled([fetchStats(), fetchAgentStats()]);
        const detData = det.status === 'fulfilled' ? det.value : null;
        const agentData = agent.status === 'fulfilled' ? agent.value : null;

        setCounts({
          alerts: detData?.open_alerts ?? 0,
          incidents: detData?.open_incidents ?? 0,
          pending: agentData?.pending_approval_count ?? 0,
        });

        if (detData) setSystemStatus('online');
        else setSystemStatus('offline');
      } catch {
        setSystemStatus('offline');
      }
    };

    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <html lang="en" className="dark">
      <head>
        <title>Aegis AI — SOC Platform</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body style={{ background: '#020817', display: 'flex', minHeight: '100vh' }}>

        {/* Sidebar */}
        <aside
          style={{
            width: '220px',
            minHeight: '100vh',
            background: 'rgba(10, 15, 30, 0.95)',
            borderRight: '1px solid #1a2744',
            display: 'flex',
            flexDirection: 'column',
            position: 'fixed',
            top: 0,
            left: 0,
            bottom: 0,
            zIndex: 50,
            backdropFilter: 'blur(20px)',
          }}
        >
          {/* Logo */}
          <div className="px-4 py-5" style={{ borderBottom: '1px solid #1a2744' }}>
            <div className="flex items-center gap-2.5 mb-1">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold"
                style={{
                  background: 'linear-gradient(135deg, #00d4ff22, #a855f722)',
                  border: '1px solid #00d4ff44',
                  color: '#00d4ff',
                }}
              >
                ⬡
              </div>
              <div>
                <div className="text-sm font-bold text-white tracking-wider">AEGIS AI</div>
                <div className="text-xs" style={{ color: '#334155' }}>SOC Platform</div>
              </div>
            </div>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-2 py-4 space-y-0.5 overflow-y-auto">
            <div className="px-3 pb-2">
              <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: '#334155' }}>
                Operations
              </span>
            </div>
            <NavItem href="/" icon="◈" label="Dashboard" active={pathname === '/'} />
            <NavItem href="/alerts" icon="⚡" label="Alerts" badge={counts.alerts} active={pathname === '/alerts'} />
            <NavItem href="/incidents" icon="🔴" label="Incidents" badge={counts.incidents} badgeColor="#ff8800" active={pathname === '/incidents'} />
            <NavItem href="/tasks" icon="◎" label="Agent Tasks" badge={counts.pending} badgeColor="#f59e0b" active={pathname === '/tasks'} />
            <NavItem href="/rules" icon="◈" label="Detection Rules" active={pathname === '/rules'} />

            <div className="px-3 pt-4 pb-2">
              <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: '#334155' }}>
                Tools
              </span>
            </div>
            <NavItem href="/simulator" icon="▶" label="Event Simulator" active={pathname === '/simulator'} />
          </nav>

          {/* System status */}
          <div className="px-4 py-4" style={{ borderTop: '1px solid #1a2744' }}>
            <div className="flex items-center gap-2.5">
              <div
                className="status-dot"
                style={{
                  background: systemStatus === 'online' ? '#00ff88' : systemStatus === 'degraded' ? '#ff8800' : '#ff4444',
                  boxShadow: `0 0 6px ${systemStatus === 'online' ? '#00ff88' : '#ff4444'}`,
                  animation: systemStatus === 'online' ? 'pulse-glow 1.5s ease-in-out infinite' : 'none',
                }}
              />
              <div>
                <div className="text-xs font-medium" style={{ color: systemStatus === 'online' ? '#00ff88' : '#ff4444' }}>
                  {systemStatus === 'online' ? 'Systems Online' : systemStatus === 'degraded' ? 'Degraded' : 'Offline'}
                </div>
                <div className="text-xs" style={{ color: '#334155' }}>Detection Engine</div>
              </div>
            </div>
          </div>
        </aside>

        {/* Main content */}
        <main style={{ marginLeft: '220px', flex: 1, minHeight: '100vh', position: 'relative' }}>
          {/* Subtle grid background */}
          <div
            className="fixed inset-0 pointer-events-none"
            style={{
              backgroundImage: 'linear-gradient(rgba(0,212,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.02) 1px, transparent 1px)',
              backgroundSize: '40px 40px',
              marginLeft: '220px',
            }}
          />
          {/* Scan line effect */}
          <div
            className="fixed pointer-events-none"
            style={{
              top: 0,
              left: '220px',
              right: 0,
              height: '1px',
              background: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.3), transparent)',
              animation: 'scan 8s linear infinite',
              zIndex: 0,
            }}
          />
          <div className="relative z-10 p-8">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}

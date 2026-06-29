'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface SidebarCounts {
  alerts: number;
  incidents: number;
  tasks: number;
  predictions: number;
  timeline: number;
}

// ─── Nav items ────────────────────────────────────────────────────────────────

const NAV = [
  { href: '/',           label: 'Dashboard',       icon: '🏠', countKey: null },
  { href: '/alerts',     label: 'Alerts',           icon: '⚡', countKey: 'alerts' },
  { href: '/incidents',  label: 'Incidents',        icon: '🔴', countKey: 'incidents' },
  { href: '/tasks',      label: 'Agent Tasks',      icon: '⚙️', countKey: 'tasks' },
  { href: '/rules',      label: 'Detection Rules',  icon: '📋', countKey: null },
  { href: '/simulator',  label: 'Event Simulator',  icon: '🧪', countKey: null },
  { href: '/defense',    label: 'Threat Defense',   icon: '🛡️', countKey: 'predictions' },
  { href: '/timeline',   label: 'Attack Timeline',  icon: '⏱️', countKey: 'timeline' },
  { href: '/graph',      label: 'Attack Graph',     icon: '🕸️', countKey: null },
] as const;

type CountKey = 'alerts' | 'incidents' | 'tasks' | 'predictions' | 'timeline';

// ─── Badge ────────────────────────────────────────────────────────────────────

function Badge({ count }: { count: number }) {
  if (count === 0) return null;
  return (
    <span
      style={{
        marginLeft: 'auto',
        background: count > 0 ? '#ff4444' : '#374151',
        color: '#fff',
        fontSize: 10,
        fontWeight: 700,
        padding: '1px 6px',
        borderRadius: 10,
        minWidth: 18,
        textAlign: 'center',
      }}
    >
      {count > 999 ? '999+' : count}
    </span>
  );
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────

export default function Sidebar() {
  const pathname = usePathname();
  const [counts, setCounts] = useState<SidebarCounts>({
    alerts: 0,
    incidents: 0,
    tasks: 0,
    predictions: 0,
    timeline: 0,
  });

  const fetchCounts = async () => {
    const results = await Promise.allSettled([
      fetch('http://localhost:8004/api/v1/alerts?limit=1').then((r) => r.json()),
      fetch('http://localhost:8004/api/v1/incidents?limit=1').then((r) => r.json()),
      fetch('http://localhost:8005/api/v1/tasks?page_size=1').then((r) => r.json()),
      fetch('http://localhost:8006/api/v1/predictions').then((r) => r.json()),
      fetch('http://localhost:8007/api/v1/timeline/stats').then((r) => r.json()),
    ]);

    const [alertsR, incidentsR, tasksR, predsR, timelineR] = results;

    setCounts({
      alerts:
        alertsR.status === 'fulfilled'
          ? alertsR.value?.total ?? (Array.isArray(alertsR.value) ? alertsR.value.length : 0)
          : 0,
      incidents:
        incidentsR.status === 'fulfilled'
          ? incidentsR.value?.total ?? (Array.isArray(incidentsR.value) ? incidentsR.value.length : 0)
          : 0,
      tasks:
        tasksR.status === 'fulfilled'
          ? tasksR.value?.total ?? (Array.isArray(tasksR.value) ? tasksR.value.length : 0)
          : 0,
      predictions:
        predsR.status === 'fulfilled'
          ? Array.isArray(predsR.value) ? predsR.value.length : (predsR.value?.total ?? 0)
          : 0,
      timeline:
        timelineR.status === 'fulfilled' ? timelineR.value?.total_events ?? 0 : 0,
    });
  };

  useEffect(() => {
    fetchCounts();
    const interval = setInterval(fetchCounts, 10_000);
    return () => clearInterval(interval);
  }, []);

  return (
    <aside
      style={{
        width: 220,
        minHeight: '100vh',
        background: '#080d1a',
        borderRight: '1px solid #1f2937',
        display: 'flex',
        flexDirection: 'column',
        padding: '20px 0',
        flexShrink: 0,
      }}
    >
      {/* Logo */}
      <div style={{ padding: '0 20px 24px', borderBottom: '1px solid #1f2937' }}>
        <div style={{ fontSize: 18, fontWeight: 800, color: '#00d4ff', letterSpacing: 1 }}>
          AEGIS AI
        </div>
        <div style={{ fontSize: 10, color: '#4b5563', marginTop: 2, textTransform: 'uppercase' }}>
          Cyber Defense OS
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '12px 0' }}>
        {NAV.map(({ href, label, icon, countKey }) => {
          const active = pathname === href || (href !== '/' && pathname.startsWith(href));
          const count = countKey ? counts[countKey as CountKey] : 0;
          return (
            <Link
              key={href}
              href={href}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '9px 20px',
                textDecoration: 'none',
                background: active ? 'rgba(0,212,255,0.08)' : 'transparent',
                borderLeft: active ? '2px solid #00d4ff' : '2px solid transparent',
                color: active ? '#00d4ff' : '#9ca3af',
                fontSize: 13,
                fontWeight: active ? 600 : 400,
                transition: 'all 0.15s',
              }}
            >
              <span style={{ fontSize: 15 }}>{icon}</span>
              <span style={{ flex: 1 }}>{label}</span>
              {countKey && <Badge count={count} />}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div
        style={{
          padding: '16px 20px',
          borderTop: '1px solid #1f2937',
          fontSize: 10,
          color: '#374151',
        }}
      >
        <div>M7 — Timeline + Graph</div>
        <div style={{ marginTop: 2 }}>Port 8007 active</div>
      </div>
    </aside>
  );
}

"use client";

interface MetricCardProps {
  label: string;
  value: number | string;
  color?: string;
  sub?: string;
}

export default function MetricCard({ label, value, color = "#00d4ff", sub }: MetricCardProps) {
  return (
    <div
      className="bg-[#0d1528] border border-[#1a2744] rounded-xl p-5 flex flex-col gap-1 transition-all duration-200 hover:border-opacity-80 group"
      style={{ boxShadow: `0 0 0 0 ${color}00` }}
      onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 0 20px ${color}22`)}
      onMouseLeave={e => (e.currentTarget.style.boxShadow = `0 0 0 0 ${color}00`)}
    >
      <span className="text-xs text-[#64748b] uppercase tracking-widest font-medium">{label}</span>
      <span className="text-3xl font-bold" style={{ color }}>{value}</span>
      {sub && <span className="text-xs text-[#64748b]">{sub}</span>}
    </div>
  );
}

"use client";

const COLORS: Record<string, string> = {
  critical: "bg-[#ff4444]/20 text-[#ff4444] border-[#ff4444]/40",
  high: "bg-[#ff8800]/20 text-[#ff8800] border-[#ff8800]/40",
  medium: "bg-[#f59e0b]/20 text-[#f59e0b] border-[#f59e0b]/40",
  low: "bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/40",
  info: "bg-[#00d4ff]/20 text-[#00d4ff] border-[#00d4ff]/40",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = COLORS[severity?.toLowerCase()] ?? COLORS.info;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}

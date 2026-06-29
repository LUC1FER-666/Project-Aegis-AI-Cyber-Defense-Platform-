"use client";

const COLORS: Record<string, string> = {
  open: "bg-[#ff4444]/20 text-[#ff4444] border-[#ff4444]/40",
  in_progress: "bg-[#ff8800]/20 text-[#ff8800] border-[#ff8800]/40",
  resolved: "bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/40",
  suppressed: "bg-[#64748b]/20 text-[#64748b] border-[#64748b]/40",
  pending_approval: "bg-[#ff8800]/20 text-[#ff8800] border-[#ff8800]/40",
  approved: "bg-[#00d4ff]/20 text-[#00d4ff] border-[#00d4ff]/40",
  executing: "bg-[#f59e0b]/20 text-[#f59e0b] border-[#f59e0b]/40",
  completed: "bg-[#00ff88]/20 text-[#00ff88] border-[#00ff88]/40",
  failed: "bg-[#ff4444]/20 text-[#ff4444] border-[#ff4444]/40",
  cancelled: "bg-[#64748b]/20 text-[#64748b] border-[#64748b]/40",
  rejected: "bg-[#64748b]/20 text-[#64748b] border-[#64748b]/40",
};

export default function StatusBadge({ status }: { status: string }) {
  const cls = COLORS[status?.toLowerCase()] ?? "bg-[#64748b]/20 text-[#64748b] border-[#64748b]/40";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${cls}`}>
      {status?.replace(/_/g, " ")}
    </span>
  );
}

"use client";

export function SkeletonRow({ cols = 5 }: { cols?: number }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-[#1a2744] rounded animate-pulse" style={{ width: `${60 + (i * 13) % 40}%` }} />
        </td>
      ))}
    </tr>
  );
}

export function SkeletonCard() {
  return (
    <div className="bg-[#0d1528] border border-[#1a2744] rounded-xl p-5 space-y-3 animate-pulse">
      <div className="h-4 bg-[#1a2744] rounded w-1/3" />
      <div className="h-3 bg-[#1a2744] rounded w-2/3" />
      <div className="h-3 bg-[#1a2744] rounded w-1/2" />
    </div>
  );
}

export function SkeletonMetric() {
  return (
    <div className="bg-[#0d1528] border border-[#1a2744] rounded-xl p-5 space-y-2 animate-pulse">
      <div className="h-3 bg-[#1a2744] rounded w-1/2" />
      <div className="h-8 bg-[#1a2744] rounded w-1/3" />
    </div>
  );
}

export default function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-6 bg-[#1a2744] rounded w-1/4" />
      <div className="h-4 bg-[#1a2744] rounded w-1/2" />
      <div className="h-4 bg-[#1a2744] rounded w-1/3" />
    </div>
  );
}

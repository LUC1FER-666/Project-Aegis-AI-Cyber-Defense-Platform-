"use client";

import { useState } from "react";

interface JsonViewerProps {
  data: unknown;
  maxHeight?: string;
}

function colorize(json: string): string {
  return json
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
      if (/^"/.test(match)) {
        if (/:$/.test(match)) return `<span style="color:#00d4ff">${match}</span>`;
        return `<span style="color:#00ff88">${match}</span>`;
      }
      if (/true|false/.test(match)) return `<span style="color:#ff8800">${match}</span>`;
      if (/null/.test(match)) return `<span style="color:#64748b">${match}</span>`;
      return `<span style="color:#f59e0b">${match}</span>`;
    });
}

export default function JsonViewer({ data, maxHeight = "300px" }: JsonViewerProps) {
  const [copied, setCopied] = useState(false);

  const json = JSON.stringify(data, null, 2);

  const copy = () => {
    navigator.clipboard.writeText(json);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="relative rounded-lg bg-[#060d1f] border border-[#1a2744] overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#1a2744]">
        <span className="text-[10px] text-[#64748b] uppercase tracking-widest font-mono">json</span>
        <button onClick={copy} className="text-[10px] text-[#64748b] hover:text-[#00d4ff] transition-colors">
          {copied ? "copied!" : "copy"}
        </button>
      </div>
      <pre
        className="p-4 text-xs font-mono overflow-auto leading-relaxed"
        style={{ maxHeight, color: "#e2e8f0" }}
        dangerouslySetInnerHTML={{ __html: colorize(json) }}
      />
    </div>
  );
}

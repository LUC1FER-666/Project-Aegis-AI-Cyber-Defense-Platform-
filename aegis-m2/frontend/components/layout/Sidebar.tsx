"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  Activity,
  Server,
  AlertTriangle,
  Brain,
  Network,
  BookOpen,
  BarChart3,
  Settings,
  FileText,
  Search,
  ChevronRight,
  Zap,
} from "lucide-react";
import { clsx } from "clsx";

const navigation = [
  {
    section: "Operations",
    items: [
      { name: "SOC Dashboard",    href: "/soc",           icon: Activity,      badge: null },
      { name: "Incidents",        href: "/incidents",     icon: AlertTriangle,  badge: "live" },
      { name: "Threat Hunting",   href: "/hunting",       icon: Search,         badge: null },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { name: "Threat Intel",     href: "/threat-intel",  icon: Shield,         badge: null },
      { name: "Knowledge Graph",  href: "/graph",         icon: Network,        badge: null },
      { name: "Digital Twin",     href: "/digital-twin",  icon: Zap,            badge: null },
    ],
  },
  {
    section: "Infrastructure",
    items: [
      { name: "Assets",           href: "/assets",        icon: Server,         badge: null },
      { name: "AI Agents",        href: "/agents",        icon: Brain,          badge: null },
    ],
  },
  {
    section: "Reporting",
    items: [
      { name: "Reports",          href: "/reports",       icon: FileText,       badge: null },
      { name: "Executive View",   href: "/executive",     icon: BarChart3,      badge: null },
      { name: "Compliance",       href: "/compliance",    icon: BookOpen,       badge: null },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 min-h-screen bg-gray-900 border-r border-gray-800 flex flex-col">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
        <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <div className="font-bold text-white text-sm tracking-wide">AEGIS AI</div>
          <div className="text-gray-500 text-xs">Cyber Defense OS</div>
        </div>
      </div>

      {/* Platform status */}
      <div className="px-4 py-3 border-b border-gray-800">
        <div className="flex items-center justify-between bg-gray-800/50 rounded-lg px-3 py-2">
          <div className="flex items-center gap-2">
            <span className="status-dot-active" />
            <span className="text-xs text-gray-300">Platform Active</span>
          </div>
          <span className="text-xs text-gray-500">Mode: Approval</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-6 overflow-y-auto">
        {navigation.map((section) => (
          <div key={section.section}>
            <p className="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
              {section.section}
            </p>
            <div className="space-y-1">
              {section.items.map((item) => {
                const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={clsx(
                      "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-150 group",
                      isActive
                        ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                        : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                    )}
                  >
                    <item.icon
                      className={clsx(
                        "w-4 h-4 flex-shrink-0",
                        isActive ? "text-cyan-400" : "text-gray-500 group-hover:text-gray-300"
                      )}
                    />
                    <span className="flex-1">{item.name}</span>
                    {item.badge === "live" && (
                      <span className="flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                      </span>
                    )}
                    {isActive && (
                      <ChevronRight className="w-3 h-3 text-cyan-400/50" />
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Bottom — settings and user */}
      <div className="px-3 py-4 border-t border-gray-800 space-y-1">
        <Link
          href="/settings"
          className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-all"
        >
          <Settings className="w-4 h-4 text-gray-500" />
          Settings
        </Link>
        <div className="flex items-center gap-3 px-3 py-2 mt-2 rounded-lg bg-gray-800/50">
          <div className="w-7 h-7 rounded-full bg-cyan-500/20 flex items-center justify-center text-xs font-bold text-cyan-400">
            A
          </div>
          <div>
            <div className="text-xs font-medium text-gray-200">Admin</div>
            <div className="text-xs text-gray-500">SOC Lead</div>
          </div>
        </div>
      </div>
    </aside>
  );
}

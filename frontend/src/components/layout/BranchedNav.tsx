import React from "react";
import {
  Activity,
  BarChart3,
  BookOpen,
  FileCode,
  RotateCcw,
  ShieldCheck,
  Zap,
} from "lucide-react";

export type NavTab =
  | "overview"
  | "redaction"
  | "restoration"
  | "taxonomy"
  | "benchmark"
  | "audit"
  | "architecture";

interface BranchedNavProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export const BranchedNav: React.FC<BranchedNavProps> = ({ currentTab, onSelectTab }) => {
  const groups = [
    {
      title: "Operations",
      items: [
        {
          id: "overview" as NavTab,
          label: "Overview & Analysis",
          icon: Zap,
          badge: "Core",
        },
        {
          id: "redaction" as NavTab,
          label: "Sanitized Prompt",
          icon: FileCode,
        },
        {
          id: "restoration" as NavTab,
          label: "Simulated Response & Decode",
          icon: RotateCcw,
        },
      ],
    },
    {
      title: "Intelligence",
      items: [
        {
          id: "taxonomy" as NavTab,
          label: "Rules & Detection Taxonomy",
          icon: BookOpen,
        },
        {
          id: "benchmark" as NavTab,
          label: "Model Benchmark & Live Eval",
          icon: BarChart3,
        },
      ],
    },
    {
      title: "Security & Audit",
      items: [
        {
          id: "audit" as NavTab,
          label: "Safe Session Activity Trail",
          icon: Activity,
        },
        {
          id: "architecture" as NavTab,
          label: "Security Model & HSM Bounds",
          icon: ShieldCheck,
        },
      ],
    },
  ];

  return (
    <nav className="w-full border-b border-slate-800 bg-[#0B132B]/80 backdrop-blur-md px-4 sm:px-6 lg:px-8 py-2">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-6">
          {groups.map((group) => (
            <div key={group.title} className="flex items-center gap-1.5">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mr-1">
                {group.title}
              </span>
              <div className="flex items-center gap-1">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = currentTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => onSelectTab(item.id)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                        isActive
                          ? "bg-sky-500/15 text-sky-300 border border-sky-500/40 shadow-sm shadow-sky-500/10"
                          : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
                      }`}
                    >
                      <Icon className={`h-3.5 w-3.5 ${isActive ? "text-sky-400" : "text-slate-400"}`} />
                      <span>{item.label}</span>
                      {item.badge && (
                        <span className="ml-1 px-1.5 py-0.2 rounded text-[9px] font-bold bg-sky-400/20 text-sky-300">
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </nav>
  );
};

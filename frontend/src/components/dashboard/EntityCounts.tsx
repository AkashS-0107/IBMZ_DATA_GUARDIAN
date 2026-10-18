import React from "react";
import { Layers } from "lucide-react";
import { Finding } from "../../api/types";

interface EntityCountsProps {
  findings: Finding[] | null;
}

export const EntityCounts: React.FC<EntityCountsProps> = ({ findings }) => {
  if (!findings || findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-6 text-center h-full">
        <Layers className="h-8 w-8 text-slate-500 mb-2" />
        <div className="text-xs font-semibold text-slate-400">No Active Findings</div>
        <p className="text-[11px] text-slate-500 mt-1">Counts appear after content inspection</p>
      </div>
    );
  }

  // Aggregate counts by entity type
  const counts: Record<string, number> = {};
  findings.forEach((f) => {
    counts[f.entity_type] = (counts[f.entity_type] || 0) + 1;
  });

  return (
    <div className="p-4 flex flex-col justify-between h-full">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Findings By Category
        </span>
        <span className="text-xs font-bold text-sky-400">{findings.length} Total</span>
      </div>

      <div className="flex flex-wrap gap-1.5 my-auto max-h-28 overflow-y-auto pr-1">
        {Object.entries(counts).map(([type, count]) => (
          <div
            key={type}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-700/80 text-xs"
          >
            <span className="font-medium text-slate-200">{type}</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-sky-500/20 text-sky-300">
              {count}
            </span>
          </div>
        ))}
      </div>

      <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800 flex justify-between">
        <span>Distinct Categories: {Object.keys(counts).length}</span>
        <span className="text-emerald-400">All Reversibly Masked</span>
      </div>
    </div>
  );
};

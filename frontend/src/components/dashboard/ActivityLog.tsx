import React from "react";
import { Activity, Clock } from "lucide-react";
import { SafeActivityEvent } from "../../api/types";

interface ActivityLogProps {
  events: SafeActivityEvent[];
  onClearLog: () => void;
}

export const ActivityLog: React.FC<ActivityLogProps> = ({ events, onClearLog }) => {
  return (
    <div className="p-4 flex flex-col justify-between h-full">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5">
          <Activity className="h-4 w-4 text-sky-400" />
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Safe Session Activity Trail ({events.length}/50)
          </span>
        </div>
        {events.length > 0 && (
          <button
            onClick={onClearLog}
            className="text-[10px] text-slate-400 hover:text-red-400 transition"
          >
            Clear Trail
          </button>
        )}
      </div>

      {events.length === 0 ? (
        <div className="text-center py-6 text-xs text-slate-500 my-auto">
          No session activity recorded yet. Run analysis or restoration to populate.
        </div>
      ) : (
        <div className="space-y-1.5 my-auto max-h-32 overflow-y-auto pr-1">
          {events.slice(0, 5).map((evt) => (
            <div
              key={evt.id}
              className="p-1.5 rounded bg-slate-900/60 border border-slate-800 text-[11px] flex items-center justify-between gap-2"
            >
              <div className="flex items-center gap-2 truncate">
                <span className="font-semibold text-slate-200 truncate">{evt.action}</span>
                {evt.risk_level !== "N/A" && (
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-slate-800 text-sky-300">
                    {evt.risk_level}
                  </span>
                )}
              </div>
              <div className="text-[10px] text-slate-500 flex items-center gap-1 shrink-0">
                <Clock className="h-2.5 w-2.5" />
                <span>{evt.timestamp.split(" ")[1] || evt.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="text-[10px] text-slate-500 pt-2 border-t border-slate-800">
        🛡️ Zero raw input text or secrets recorded in audit log.
      </div>
    </div>
  );
};

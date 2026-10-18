import React from "react";
import { Activity, Trash2, ShieldCheck } from "lucide-react";
import { SafeActivityEvent } from "../../api/types";

interface SafeActivityLogViewProps {
  events: SafeActivityEvent[];
  onClearLog: () => void;
}

export const SafeActivityLogView: React.FC<SafeActivityLogViewProps> = ({ events, onClearLog }) => {
  return (
    <div className="space-y-4">
      <div className="guardian-card p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-sky-400" />
              <h2 className="text-base font-bold text-slate-100">Safe Session Activity Trail</h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              In-memory audit summary of actions executed during this active browser session.
              Strictly safe metadata: zero raw input strings or sensitive values are recorded.
            </p>
          </div>

          {events.length > 0 && (
            <button
              onClick={onClearLog}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-950/40 hover:bg-red-900/50 text-red-300 text-xs font-medium border border-red-800/40 transition"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>Clear Activity Trail</span>
            </button>
          )}
        </div>
      </div>

      <div className="guardian-card overflow-hidden">
        {events.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No activity recorded in this session yet. Run an analysis or local restoration to populate.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0F172A] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4 font-semibold">#</th>
                  <th className="py-2.5 px-4 font-semibold">Timestamp (UTC)</th>
                  <th className="py-2.5 px-4 font-semibold">Action Performed</th>
                  <th className="py-2.5 px-4 font-semibold">Risk Level</th>
                  <th className="py-2.5 px-4 font-semibold">Entities Detected</th>
                  <th className="py-2.5 px-4 font-semibold">Operation Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono">
                {events.map((evt, idx) => (
                  <tr key={evt.id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 text-slate-500">{events.length - idx}</td>
                    <td className="py-2.5 px-4 text-slate-300">{evt.timestamp}</td>
                    <td className="py-2.5 px-4 font-sans font-semibold text-sky-300">{evt.action}</td>
                    <td className="py-2.5 px-4 font-sans">
                      {evt.risk_level !== "N/A" ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 border border-slate-700 text-slate-200">
                          {evt.risk_level}
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">{evt.entity_counts}</td>
                    <td className="py-2.5 px-4 text-emerald-400 font-sans">{evt.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" />
        <span>
          <b>Privacy Assurance:</b> This audit trail is retained strictly in client memory (max 50 events)
          and does not log or persist submitted prompt content.
        </span>
      </div>
    </div>
  );
};

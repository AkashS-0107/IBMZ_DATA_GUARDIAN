import React from "react";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { Finding, Severity } from "../../api/types";

interface FindingsTableProps {
  findings: Finding[];
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings }) => {
  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500/15 text-red-400 border-red-500/30";
      case "High":
        return "bg-orange-500/15 text-orange-400 border-orange-500/30";
      case "Medium":
        return "bg-amber-500/15 text-amber-400 border-amber-500/30";
      case "Low":
      default:
        return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
    }
  };

  if (!findings || findings.length === 0) {
    return (
      <div className="guardian-card p-6 flex flex-col items-center justify-center text-center">
        <CheckCircle2 className="h-10 w-10 text-emerald-400 mb-2" />
        <h3 className="text-sm font-semibold text-slate-200">Zero Sensitive Entities Detected</h3>
        <p className="text-xs text-slate-400 max-w-md mt-1">
          No PII, API tokens, database connection credentials, or high-entropy secrets were found in the inspected content.
        </p>
      </div>
    );
  }

  return (
    <div className="guardian-card overflow-hidden">
      <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-sky-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            2. Structured Findings ({findings.length})
          </h3>
        </div>
        <span className="text-[11px] text-slate-400">
          Raw sensitive values strictly excluded from view
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0F172A] text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-4 font-semibold">#</th>
              <th className="py-2.5 px-4 font-semibold">Entity Type</th>
              <th className="py-2.5 px-4 font-semibold">Risk Tier</th>
              <th className="py-2.5 px-4 font-semibold">Detection Method</th>
              <th className="py-2.5 px-4 font-semibold">Span [Start, End)</th>
              <th className="py-2.5 px-4 font-semibold">Length</th>
              <th className="py-2.5 px-4 font-semibold">Safe Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 font-mono">
            {findings.map((f, idx) => (
              <tr key={`${f.rule_id}-${f.start}-${idx}`} className="hover:bg-slate-800/40 transition">
                <td className="py-2.5 px-4 text-slate-400">{idx + 1}</td>
                <td className="py-2.5 px-4 font-semibold text-sky-300 font-sans">{f.entity_type}</td>
                <td className="py-2.5 px-4 font-sans">
                  <span
                    className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${getSeverityBadge(
                      f.severity
                    )}`}
                  >
                    {f.severity}
                  </span>
                </td>
                <td className="py-2.5 px-4 text-slate-300">{f.rule_id}</td>
                <td className="py-2.5 px-4 text-slate-400">
                  [{f.start}, {f.end})
                </td>
                <td className="py-2.5 px-4 text-slate-400">{f.span_length} chars</td>
                <td className="py-2.5 px-4 text-slate-300 font-sans max-w-xs truncate" title={f.description}>
                  {f.description}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

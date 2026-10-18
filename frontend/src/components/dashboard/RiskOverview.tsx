import React from "react";
import { AlertOctagon, CheckCircle2, ShieldAlert } from "lucide-react";
import { RiskSummary, Severity } from "../../api/types";

interface RiskOverviewProps {
  risk: RiskSummary | null;
}

export const RiskOverview: React.FC<RiskOverviewProps> = ({ risk }) => {
  if (!risk) {
    return (
      <div className="flex flex-col items-center justify-center p-6 text-center h-full">
        <ShieldAlert className="h-8 w-8 text-slate-500 mb-2" />
        <div className="text-xs font-semibold text-slate-400">Idle / Awaiting Analysis</div>
        <p className="text-[11px] text-slate-500 mt-1">Run inspection to populate risk tier</p>
      </div>
    );
  }

  const getTierColor = (level: Severity) => {
    switch (level) {
      case "Critical":
        return "text-red-400 bg-red-500/10 border-red-500/30";
      case "High":
        return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "Medium":
        return "text-amber-400 bg-amber-500/10 border-amber-500/30";
      case "Low":
      default:
        return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
    }
  };

  return (
    <div className="p-4 flex flex-col justify-between h-full">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Exposure Risk Tier
        </span>
        <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border ${getTierColor(risk.risk_level)}`}>
          {risk.risk_level}
        </span>
      </div>

      <div className="my-3">
        <div className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          {risk.risk_level === "Critical" ? (
            <AlertOctagon className="h-6 w-6 text-red-400" />
          ) : (
            <CheckCircle2 className="h-6 w-6 text-emerald-400" />
          )}
          <span>{risk.risk_level.toUpperCase()}</span>
        </div>
        <p className="text-xs text-slate-400 mt-1 line-clamp-2">
          {risk.reasons[0] || "No exposure detected."}
        </p>
      </div>

      <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800 flex justify-between">
        <span>Total Findings: {risk.findings_count}</span>
        <span>Critical: {risk.critical_count}</span>
      </div>
    </div>
  );
};

import React from "react";
import { AlertOctagon, AlertTriangle, CheckCircle, Info, ShieldCheck } from "lucide-react";
import { RiskSummary, Severity } from "../../api/types";

interface RiskAssessmentCardProps {
  risk: RiskSummary;
}

export const RiskAssessmentCard: React.FC<RiskAssessmentCardProps> = ({ risk }) => {
  const getBannerDetails = (level: Severity) => {
    switch (level) {
      case "Critical":
        return {
          icon: AlertOctagon,
          title: "CRITICAL EXPOSURE RISK",
          bg: "bg-red-950/40 border-red-500/40 text-red-200",
          badge: "bg-red-500/20 text-red-400 border-red-500/40",
          glow: "glow-critical",
        };
      case "High":
        return {
          icon: AlertTriangle,
          title: "HIGH EXPOSURE RISK",
          bg: "bg-orange-950/40 border-orange-500/40 text-orange-200",
          badge: "bg-orange-500/20 text-orange-400 border-orange-500/40",
          glow: "",
        };
      case "Medium":
        return {
          icon: Info,
          title: "MEDIUM EXPOSURE RISK",
          bg: "bg-amber-950/40 border-amber-500/40 text-amber-200",
          badge: "bg-amber-500/20 text-amber-400 border-amber-500/40",
          glow: "",
        };
      case "Low":
      default:
        return {
          icon: CheckCircle,
          title: "LOW EXPOSURE RISK",
          bg: "bg-emerald-950/40 border-emerald-500/40 text-emerald-200",
          badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
          glow: "",
        };
    }
  };

  const details = getBannerDetails(risk.risk_level);
  const Icon = details.icon;

  return (
    <div className={`guardian-card p-5 border ${details.bg} ${details.glow}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <Icon className="h-5 w-5 text-current" />
          <h3 className="text-sm font-bold tracking-wide">{details.title}</h3>
        </div>
        <span
          className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${details.badge}`}
        >
          {risk.risk_level} Tier
        </span>
      </div>

      <div className="grid grid-cols-4 gap-2 mb-4 text-center">
        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Critical</div>
          <div className="text-sm font-bold text-red-400">{risk.critical_count}</div>
        </div>
        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">High</div>
          <div className="text-sm font-bold text-orange-400">{risk.high_count}</div>
        </div>
        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Medium</div>
          <div className="text-sm font-bold text-amber-400">{risk.medium_count}</div>
        </div>
        <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Low</div>
          <div className="text-sm font-bold text-emerald-400">{risk.low_count}</div>
        </div>
      </div>

      <div>
        <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
          Audit Rationale & Contributing Factors:
        </h4>
        <ul className="space-y-1.5 text-xs text-slate-300">
          {risk.reasons.map((reason, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span className="text-sky-400 font-bold shrink-0">•</span>
              <span>{reason}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center gap-1.5">
        <ShieldCheck className="h-4 w-4 text-sky-400 shrink-0" />
        <span>
          Evaluated deterministically by Python risk engine. Defense-in-depth prototype for IBM Z Challenge.
        </span>
      </div>
    </div>
  );
};

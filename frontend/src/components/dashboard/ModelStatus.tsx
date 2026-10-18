import React from "react";
import { CheckCircle2, AlertCircle } from "lucide-react";
import { SystemStatus } from "../../api/types";

interface ModelStatusProps {
  status: SystemStatus | null;
}

export const ModelStatus: React.FC<ModelStatusProps> = ({ status }) => {
  const isMlAvailable = Boolean(status?.ml_available);
  const isBackendReady = status?.backend_status === "ready";

  return (
    <div className="p-4 flex flex-col justify-between h-full">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Engine & Model State
        </span>
        <div className="flex items-center gap-1">
          <span
            className={`h-2 w-2 rounded-full ${
              isBackendReady ? "bg-emerald-400 animate-pulse" : "bg-red-400"
            }`}
          />
          <span className="text-xs text-slate-300 font-medium">
            {isBackendReady ? "Online" : "Connecting"}
          </span>
        </div>
      </div>

      <div className="my-2 space-y-1.5 text-xs">
        <div className="flex items-center justify-between p-1.5 rounded bg-slate-900/60 border border-slate-800">
          <span className="text-slate-400">Detection Architecture:</span>
          <span className="font-semibold text-sky-400">
            {isMlAvailable ? "Hybrid (Rules + NER)" : "Rules-Only Fallback"}
          </span>
        </div>

        <div className="flex items-center justify-between p-1.5 rounded bg-slate-900/60 border border-slate-800">
          <span className="text-slate-400">spaCy English NER:</span>
          <span className={`font-semibold flex items-center gap-1 ${isMlAvailable ? "text-emerald-400" : "text-amber-400"}`}>
            {isMlAvailable ? <CheckCircle2 className="h-3 w-3" /> : <AlertCircle className="h-3 w-3" />}
            {isMlAvailable ? "Loaded & Ready" : "Offline (Safe Fallback)"}
          </span>
        </div>

        <div className="flex items-center justify-between p-1.5 rounded bg-slate-900/60 border border-slate-800">
          <span className="text-slate-400">Rule Taxonomy:</span>
          <span className="font-semibold text-slate-200">15 Patterns + Shannon H</span>
        </div>
      </div>

      <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800 flex justify-between">
        <span>Target: LinuxONE s390x / Win</span>
        <span>Python {status?.python_version || "3.13"}</span>
      </div>
    </div>
  );
};

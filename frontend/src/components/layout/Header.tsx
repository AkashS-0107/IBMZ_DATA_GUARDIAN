import React from "react";
import { Shield, Cpu, Lock, CheckCircle2, RefreshCw } from "lucide-react";
import { SystemStatus } from "../../api/types";

interface HeaderProps {
  status: SystemStatus | null;
  isLoading: boolean;
  onRefresh: () => void;
  activeVaultCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  status,
  isLoading,
  onRefresh,
  activeVaultCount,
}) => {
  const isBackendReady = status?.backend_status === "ready";
  const isMlAvailable = Boolean(status?.ml_available);

  return (
    <header className="relative z-10 border-b border-slate-800 bg-[#0B132B]/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand & IBM Z Hackathon Context */}
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 p-0.5 shadow-lg shadow-sky-500/20 flex items-center justify-center">
            <div className="h-full w-full bg-[#0B132B] rounded-[10px] flex items-center justify-center">
              <Shield className="h-5 w-5 text-sky-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                AI Data Leak Guardian
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-semibold tracking-wider uppercase rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/30">
                v2.0 Hybrid
              </span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-1.5">
              <span>IBM Z Challenge:</span>
              <span className="text-sky-400 font-medium">AI Secured — Innovation Without Exposure</span>
            </p>
          </div>
        </div>

        {/* Live Status Ribbon */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Backend Status */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
              isBackendReady
                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                : "bg-red-500/10 text-red-400 border-red-500/30"
            }`}
            data-testid="status-backend"
          >
            <span
              className={`h-2 w-2 rounded-full ${
                isBackendReady ? "bg-emerald-400 animate-pulse" : "bg-red-400"
              }`}
            />
            <span>{isBackendReady ? "Backend: Ready" : "Backend: Offline"}</span>
          </div>

          {/* Rules Engine Status */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-sky-500/10 text-sky-400 border-sky-500/30"
            data-testid="status-rules"
          >
            <Lock className="h-3.5 w-3.5 text-sky-400" />
            <span>Rules: Active</span>
          </div>

          {/* ML Model Status */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
              isMlAvailable
                ? "bg-indigo-500/10 text-indigo-300 border-indigo-500/30"
                : "bg-amber-500/10 text-amber-300 border-amber-500/30"
            }`}
            data-testid="status-ml"
          >
            <Cpu className="h-3.5 w-3.5" />
            <span>{isMlAvailable ? "Hybrid: spaCy NER" : "Rules-Only Fallback"}</span>
          </div>

          {/* In-Memory Vault Status */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-slate-800 text-slate-300 border-slate-700"
            data-testid="status-vault"
          >
            <CheckCircle2 className="h-3.5 w-3.5 text-sky-400" />
            <span>Vault: {activeVaultCount} Keys</span>
          </div>

          {/* Refresh Action */}
          <button
            onClick={onRefresh}
            disabled={isLoading}
            title="Refresh System Status"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition disabled:opacity-50"
            aria-label="Refresh Status"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>
    </header>
  );
};

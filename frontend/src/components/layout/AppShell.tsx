import React from "react";
import { Header } from "./Header";
import { BranchedNav, NavTab } from "./BranchedNav";
import { BackgroundGrid } from "./BackgroundGrid";
import { SystemStatus } from "../../api/types";

interface AppShellProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  status: SystemStatus | null;
  isLoadingStatus: boolean;
  onRefreshStatus: () => void;
  activeVaultCount: number;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  currentTab,
  onSelectTab,
  status,
  isLoadingStatus,
  onRefreshStatus,
  activeVaultCount,
  children,
}) => {
  return (
    <div className="min-h-screen bg-[#0B132B] text-slate-100 flex flex-col relative selection:bg-sky-500/30 selection:text-sky-200">
      <BackgroundGrid />

      {/* Main Header */}
      <Header
        status={status}
        isLoading={isLoadingStatus}
        onRefresh={onRefreshStatus}
        activeVaultCount={activeVaultCount}
      />

      {/* Branched Navigation */}
      <BranchedNav currentTab={currentTab} onSelectTab={onSelectTab} />

      {/* Main Viewport Container */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {children}
      </main>

      {/* Accessible Footer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-[#0B132B]/90 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            AI Data Leak Guardian &copy; 2026 &mdash; Built for IBM Z Hackathon Challenge:{" "}
            <span className="text-slate-400">AI Secured: Innovation Without Exposure</span>
          </div>
          <div className="flex items-center gap-4 text-[11px] text-slate-400">
            <span>Target: IBM LinuxONE s390x</span>
            <span>Vite + React 18 + FastAPI</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

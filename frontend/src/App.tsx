import React, { useEffect, useState, useMemo } from "react";
import { AppShell } from "./components/layout/AppShell";
import { NavTab } from "./components/layout/BranchedNav";
import { AnalysisWorkspace } from "./components/analysis/AnalysisWorkspace";
import { FindingsTable } from "./components/analysis/FindingsTable";
import { RiskAssessmentCard } from "./components/analysis/RiskAssessmentCard";
import { RedactedOutput } from "./components/analysis/RedactedOutput";
import { RestorationPanel } from "./components/analysis/RestorationPanel";
import { DashboardGrid } from "./components/dashboard/DashboardGrid";
import { DetectionTaxonomy } from "./components/intelligence/DetectionTaxonomy";
import { ModelBenchmarkView } from "./components/intelligence/ModelBenchmarkView";
import { SafeActivityLogView } from "./components/security/SafeActivityLogView";
import { SecurityArchitectureView } from "./components/security/SecurityArchitectureView";
import { api } from "./api/client";
import {
  AnalyzeResponse,
  EvaluationMetricsResponse,
  PresetItem,
  RestoreResponse,
  SafeActivityEvent,
  SystemStatus,
} from "./api/types";

function generateSessionId(): string {
  return `sess_${Math.random().toString(36).substring(2, 9)}_${Date.now().toString(36)}`;
}

export const App: React.FC = () => {
  // Navigation & View State
  const [currentTab, setCurrentTab] = useState<NavTab>("overview");

  // System & Backend State
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [isLoadingStatus, setIsLoadingStatus] = useState(false);
  const [metrics, setMetrics] = useState<EvaluationMetricsResponse | null>(null);

  // Session Vault State
  const [sessionId, setSessionId] = useState<string>(generateSessionId);
  const [activeVaultCount, setActiveVaultCount] = useState<number>(0);

  // Presets & Input State
  const [presets, setPresets] = useState<PresetItem[]>([]);
  const [selectedPresetId, setSelectedPresetId] = useState<string>("");
  const [inputText, setInputText] = useState<string>("");
  const [analyzedText, setAnalyzedText] = useState<string>("");
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);

  // Analysis Results State
  const [analysisResult, setAnalysisResult] = useState<AnalyzeResponse | null>(null);

  // Restoration State
  const [restorationResult, setRestorationResult] = useState<RestoreResponse | null>(null);
  const [isRestoring, setIsRestoring] = useState<boolean>(false);

  // Bounded Safe Activity Log (Max 50 events)
  const [activityEvents, setActivityEvents] = useState<SafeActivityEvent[]>([]);

  const logActivity = (action: string, riskLevel = "N/A", entityCounts = "None", status = "Success") => {
    const newEvent: SafeActivityEvent = {
      id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
      timestamp: new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC",
      action,
      risk_level: riskLevel,
      entity_counts: entityCounts,
      status,
    };
    setActivityEvents((prev) => [newEvent, ...prev].slice(0, 50));
  };

  // Staleness calculation: if input changed since analysis was executed
  const isStale = useMemo(() => {
    return Boolean(analysisResult && inputText.trim() !== analyzedText.trim());
  }, [analysisResult, inputText, analyzedText]);

  // Initial Data Fetching
  const fetchStatusAndData = async () => {
    setIsLoadingStatus(true);
    try {
      const [statusRes, presetsRes, metricsRes] = await Promise.allSettled([
        api.getStatus(),
        api.getPresets(),
        api.getEvaluationMetrics(),
      ]);

      if (statusRes.status === "fulfilled") {
        setSystemStatus(statusRes.value);
      }
      if (presetsRes.status === "fulfilled") {
        setPresets(presetsRes.value.presets);
      }
      if (metricsRes.status === "fulfilled") {
        setMetrics(metricsRes.value);
      }
    } catch {
      // Silently handled by state fallbacks
    } finally {
      setIsLoadingStatus(false);
    }
  };

  useEffect(() => {
    fetchStatusAndData();
  }, []);

  // Preset Handlers
  const handleLoadPreset = () => {
    const selected = presets.find((p) => p.id === selectedPresetId);
    if (selected) {
      setInputText(selected.content);
      logActivity(`Loaded Synthetic Preset (${selected.title.split(":")[0]})`, "N/A", "None", "Ready for Inspection");
    }
  };

  // Primary Analysis Execution
  const handleAnalyze = async () => {
    if (!inputText.trim()) return;

    setIsAnalyzing(true);
    try {
      const response = await api.analyze(inputText, sessionId);
      setSessionId(response.session_id);
      setAnalysisResult(response);
      setAnalyzedText(inputText);
      setActiveVaultCount(response.redaction.placeholders_count);
      setRestorationResult(null);

      // Summarize entity counts for safe audit log
      const counts: Record<string, number> = {};
      response.findings.forEach((f) => {
        counts[f.entity_type] = (counts[f.entity_type] || 0) + 1;
      });
      const summaryStr =
        Object.entries(counts)
          .map(([k, v]) => `${k}:${v}`)
          .join(", ") || "None";

      logActivity(
        "Analyzed & Redacted",
        response.risk.risk_level,
        summaryStr,
        `Redacted ${response.redaction.placeholders_count} tokens`
      );
    } catch (err: any) {
      logActivity("Analysis Failed", "N/A", "None", `Error: ${err.message || "Failed"}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Workspace Actions
  const handleClearAnalysis = () => {
    setInputText("");
    setAnalyzedText("");
    setAnalysisResult(null);
    logActivity("Cleared Workspace", "N/A", "None", "Workspace Cleared (Vault Intact)");
  };

  const handleResetSession = async () => {
    try {
      await api.resetSession(sessionId);
    } catch {
      // Ignored
    }
    const newSid = generateSessionId();
    setSessionId(newSid);
    setActiveVaultCount(0);
    setInputText("");
    setAnalyzedText("");
    setAnalysisResult(null);
    setRestorationResult(null);
    logActivity("Session Reset & Vault Purged", "N/A", "None", "Purged (0 active keys)");
  };

  // Restoration Handlers
  const handleRestore = async (aiResponse: string) => {
    setIsRestoring(true);
    try {
      const response = await api.restore(sessionId, aiResponse);
      setRestorationResult(response);
      logActivity(
        "Restored Placeholders Locally",
        "N/A",
        "None",
        `Restored ${response.restored_placeholders.length} tokens`
      );
    } catch (err: any) {
      logActivity("Restoration Failed", "N/A", "None", `Error: ${err.message || "Failed"}`);
    } finally {
      setIsRestoring(false);
    }
  };

  const handlePurgeVault = async () => {
    try {
      await api.resetSession(sessionId);
      setActiveVaultCount(0);
      setRestorationResult(null);
      logActivity("Purged Session Vault", "N/A", "None", "Vault Cleared (0 active keys)");
    } catch (err: any) {
      logActivity("Vault Purge Failed", "N/A", "None", `Error: ${err.message || "Failed"}`);
    }
  };

  // Recognized placeholders for auto-generate template
  const recognizedPlaceholders = useMemo(() => {
    if (!analysisResult) return [];
    const matches = analysisResult.redaction.masked_text.match(/\[[A-Z_]+_\d+\]/g) || [];
    return Array.from(new Set(matches));
  }, [analysisResult]);

  return (
    <AppShell
      currentTab={currentTab}
      onSelectTab={setCurrentTab}
      status={systemStatus}
      isLoadingStatus={isLoadingStatus}
      onRefreshStatus={fetchStatusAndData}
      activeVaultCount={activeVaultCount}
    >
      {/* 1. OPERATIONS: OVERVIEW & ANALYSIS */}
      {currentTab === "overview" && (
        <div className="space-y-6">
          {/* Draggable Dashboard Widgets Grid */}
          <DashboardGrid
            risk={isStale ? null : analysisResult?.risk || null}
            findings={isStale ? null : analysisResult?.findings || null}
            status={systemStatus}
            metrics={metrics}
            activityEvents={activityEvents}
            onClearActivityLog={() => setActivityEvents([])}
          />

          {/* Primary Analysis Workspace */}
          <AnalysisWorkspace
            inputText={inputText}
            onChangeInput={setInputText}
            onAnalyze={handleAnalyze}
            onClearAnalysis={handleClearAnalysis}
            onResetSession={handleResetSession}
            isAnalyzing={isAnalyzing}
            isStale={isStale}
            presets={presets}
            selectedPresetId={selectedPresetId}
            onSelectPreset={setSelectedPresetId}
            onLoadPreset={handleLoadPreset}
          />

          {/* Active Findings and Risk (Hidden when Stale) */}
          {analysisResult && !isStale && (
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
              <div className="lg:col-span-3">
                <FindingsTable findings={analysisResult.findings} />
              </div>
              <div className="lg:col-span-2">
                <RiskAssessmentCard risk={analysisResult.risk} />
              </div>
            </div>
          )}

          {/* Redacted Sanitized Output (Hidden when Stale) */}
          {analysisResult && !isStale && (
            <RedactedOutput redaction={analysisResult.redaction} />
          )}

          {/* Simulated Restoration Panel */}
          <RestorationPanel
            sessionId={sessionId}
            recognizedPlaceholders={recognizedPlaceholders}
            onRestore={handleRestore}
            onPurgeVault={handlePurgeVault}
            restorationResult={restorationResult}
            isRestoring={isRestoring}
          />
        </div>
      )}

      {/* 2. OPERATIONS: SANITIZED REDACTION VAULT */}
      {currentTab === "redaction" && (
        <div className="space-y-6">
          {analysisResult && !isStale ? (
            <RedactedOutput redaction={analysisResult.redaction} />
          ) : (
            <div className="guardian-card p-8 text-center text-xs text-slate-400">
              No sanitized prompt currently active. Run an inspection in the <b>Overview & Analysis</b> workspace first.
            </div>
          )}
        </div>
      )}

      {/* 3. OPERATIONS: SIMULATED RESPONSE & RESTORATION */}
      {currentTab === "restoration" && (
        <div className="space-y-6">
          <RestorationPanel
            sessionId={sessionId}
            recognizedPlaceholders={recognizedPlaceholders}
            onRestore={handleRestore}
            onPurgeVault={handlePurgeVault}
            restorationResult={restorationResult}
            isRestoring={isRestoring}
          />
        </div>
      )}

      {/* 4. INTELLIGENCE: TAXONOMY */}
      {currentTab === "taxonomy" && <DetectionTaxonomy />}

      {/* 5. INTELLIGENCE: BENCHMARK */}
      {currentTab === "benchmark" && (
        <ModelBenchmarkView metrics={metrics} onRefreshMetrics={fetchStatusAndData} />
      )}

      {/* 6. SECURITY: AUDIT TRAIL */}
      {currentTab === "audit" && (
        <SafeActivityLogView events={activityEvents} onClearLog={() => setActivityEvents([])} />
      )}

      {/* 7. SECURITY: ARCHITECTURE */}
      {currentTab === "architecture" && <SecurityArchitectureView />}
    </AppShell>
  );
};

export default App;

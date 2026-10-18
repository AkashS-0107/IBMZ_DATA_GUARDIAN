import React from "react";
import { Play, Eraser, Trash2, AlertCircle, ShieldAlert, Sparkles } from "lucide-react";
import { PresetItem } from "../../api/types";

interface AnalysisWorkspaceProps {
  inputText: string;
  onChangeInput: (text: string) => void;
  onAnalyze: () => void;
  onClearAnalysis: () => void;
  onResetSession: () => void;
  isAnalyzing: boolean;
  isStale: boolean;
  presets: PresetItem[];
  selectedPresetId: string;
  onSelectPreset: (presetId: string) => void;
  onLoadPreset: () => void;
}

export const AnalysisWorkspace: React.FC<AnalysisWorkspaceProps> = ({
  inputText,
  onChangeInput,
  onAnalyze,
  onClearAnalysis,
  onResetSession,
  isAnalyzing,
  isStale,
  presets,
  selectedPresetId,
  onSelectPreset,
  onLoadPreset,
}) => {
  return (
    <div className="guardian-card p-5">
      {/* Header & Presets Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-sky-400" />
            <span>1. Sensitive Data Inspection Workspace</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Content is inspected strictly in local memory before reaching downstream AI systems.
          </p>
        </div>

        {/* Preset Selector */}
        <div className="flex items-center gap-2">
          <select
            value={selectedPresetId}
            onChange={(e) => onSelectPreset(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-sky-500 max-w-[280px]"
            aria-label="Select Synthetic Preset"
          >
            <option value="">Select a synthetic demo preset...</option>
            {presets.map((preset) => (
              <option key={preset.id} value={preset.id}>
                {preset.title}
              </option>
            ))}
          </select>
          <button
            onClick={onLoadPreset}
            disabled={!selectedPresetId}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-xs font-medium text-slate-200 rounded-lg border border-slate-700 transition"
          >
            <Sparkles className="h-3.5 w-3.5 text-sky-400" />
            <span>Load Preset</span>
          </button>
        </div>
      </div>

      {/* Input Text Area */}
      <div className="relative">
        <textarea
          value={inputText}
          onChange={(e) => onChangeInput(e.target.value)}
          placeholder="Paste prompts, code snippets, database connection strings, or system configuration payloads here for local risk inspection..."
          rows={6}
          className="w-full bg-[#0F172A] border border-slate-700/80 rounded-lg p-3.5 text-sm text-slate-200 font-mono placeholder:font-sans placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500 transition resize-y"
          aria-label="Input content for inspection"
        />
      </div>

      {/* Staleness Warning Banner */}
      {isStale && (
        <div
          role="alert"
          className="mt-3 flex items-start gap-2.5 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs"
        >
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
          <div>
            <span className="font-semibold">Input was modified after analysis:</span> Previous detection
            findings and risk assessment are currently veiled to prevent applying stale results to newly edited text.
            Click <b>Analyze & Redact</b> below to inspect updated text.
          </div>
        </div>
      )}

      {/* Action Controls Row */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800">
        <div className="flex items-center gap-2">
          <button
            onClick={onAnalyze}
            disabled={isAnalyzing || !inputText.trim()}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs shadow-md shadow-sky-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition"
          >
            <Play className={`h-4 w-4 ${isAnalyzing ? "animate-spin" : ""}`} />
            <span>{isAnalyzing ? "Inspecting & Redacting..." : "🛡️ Analyze & Redact"}</span>
          </button>

          <button
            onClick={onClearAnalysis}
            disabled={!inputText && !isStale}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium border border-slate-700 transition disabled:opacity-40"
          >
            <Eraser className="h-3.5 w-3.5" />
            <span>Clear Workspace</span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onResetSession}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-red-950/40 hover:bg-red-900/50 text-red-300 hover:text-red-200 text-xs font-medium border border-red-800/40 transition"
            title="Purge session vault and reset identifiers"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>Reset Session & Vault</span>
          </button>
        </div>
      </div>
    </div>
  );
};

import React, { useState } from "react";
import { AlertTriangle, CheckCircle, Lock, ShieldCheck, Sparkles, Trash2, Unlock } from "lucide-react";
import { RestoreResponse } from "../../api/types";

interface RestorationPanelProps {
  sessionId: string;
  recognizedPlaceholders: string[];
  onRestore: (aiResponse: string) => Promise<void>;
  onPurgeVault: () => Promise<void>;
  restorationResult: RestoreResponse | null;
  isRestoring: boolean;
}

export const RestorationPanel: React.FC<RestorationPanelProps> = ({
  sessionId,
  recognizedPlaceholders,
  onRestore,
  onPurgeVault,
  restorationResult,
  isRestoring,
}) => {
  const [responseInput, setResponseInput] = useState("");

  const handleAutoGenerateTemplate = () => {
    if (recognizedPlaceholders.length === 0) {
      setResponseInput("Thank you for your prompt. No sensitive placeholders were detected or replaced.");
    } else {
      const sample = recognizedPlaceholders.slice(0, 3).join(" and ");
      setResponseInput(
        `Hello! We received your prompt referencing ${sample}. Your deployment parameters and authorization keys have been verified successfully.`
      );
    }
  };

  const handleInjectForeignToken = () => {
    const foreign = "[FOREIGN_KEY_99]";
    setResponseInput((prev) =>
      prev ? `${prev}\nAttached foreign cloud service token: ${foreign}` : `Foreign response token: ${foreign}`
    );
  };

  const handleRestoreClick = () => {
    if (responseInput.trim()) {
      onRestore(responseInput);
    }
  };

  return (
    <div className="guardian-card p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Unlock className="h-4 w-4 text-emerald-400" />
            <span>4. Simulated AI Response & Local Placeholder Restoration</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Demonstrates how an AI completion containing placeholders is safely decoded in local memory.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleAutoGenerateTemplate}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition"
            title="Generate simulated response referencing active session placeholders"
          >
            <Sparkles className="h-3.5 w-3.5 text-sky-400" />
            <span>Auto-Generate Template</span>
          </button>

          <button
            onClick={handleInjectForeignToken}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-amber-300 border border-amber-800/40 transition"
            title="Inject unrecognized foreign placeholder to test security boundary"
          >
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            <span>Inject Foreign Token</span>
          </button>
        </div>
      </div>

      <div className="relative">
        <textarea
          value={responseInput}
          onChange={(e) => setResponseInput(e.target.value)}
          placeholder="Paste or generate a simulated AI completion containing placeholders like [EMAIL_1] or [API_KEY_1]..."
          rows={4}
          className="w-full bg-[#0F172A] border border-slate-700/80 rounded-lg p-3 text-xs text-slate-200 font-mono placeholder:font-sans placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 transition resize-y"
          aria-label="Simulated AI response input"
        />
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <button
            onClick={handleRestoreClick}
            disabled={isRestoring || !responseInput.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs shadow-md shadow-emerald-600/20 disabled:opacity-40 transition"
          >
            <Unlock className="h-3.5 w-3.5" />
            <span>{isRestoring ? "Restoring..." : "🔓 Restore Response Locally"}</span>
          </button>

          <button
            onClick={onPurgeVault}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-red-950/40 hover:bg-red-900/50 text-red-300 text-xs font-medium border border-red-800/40 transition"
            title="Purge session vault to demonstrate restoration failure"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>Purge Vault Mappings</span>
          </button>
        </div>

        <div className="text-[11px] text-slate-400 flex items-center gap-1">
          <Lock className="h-3.5 w-3.5 text-sky-400" />
          <span>Active Session ID: <code className="text-sky-300">{sessionId}</code></span>
        </div>
      </div>

      {/* Restored Results Section */}
      {restorationResult && (
        <div className="mt-4 pt-4 border-t border-slate-800 space-y-3">
          <div>
            <div className="text-xs font-semibold text-emerald-400 mb-1.5 flex items-center gap-1.5">
              <CheckCircle className="h-3.5 w-3.5" />
              <span>Locally Decoded Output:</span>
            </div>
            <pre className="w-full bg-[#0F172A] border border-emerald-500/30 rounded-lg p-3 text-xs text-slate-100 font-mono whitespace-pre-wrap select-all">
              {restorationResult.restored_text}
            </pre>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {/* Restored Tokens */}
            <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30">
              <div className="text-[10px] uppercase font-bold text-emerald-400 tracking-wider mb-1">
                Restored in This Session ({restorationResult.restored_placeholders.length})
              </div>
              <div className="font-mono text-slate-200">
                {restorationResult.restored_placeholders.length > 0
                  ? restorationResult.restored_placeholders.join(", ")
                  : "None"}
              </div>
            </div>

            {/* Unrestored Tokens */}
            <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/30">
              <div className="text-[10px] uppercase font-bold text-amber-400 tracking-wider mb-1">
                Unknown / Preserved Untouched ({restorationResult.unrestored_placeholders.length})
              </div>
              <div className="font-mono text-amber-300">
                {restorationResult.unrestored_placeholders.length > 0
                  ? restorationResult.unrestored_placeholders.join(", ")
                  : "None"}
              </div>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
            <ShieldCheck className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" />
            <div>
              <b>Strict Security Boundary:</b> Unknown placeholders and tokens originating from foreign sessions
              remain intact. Restored text is treated strictly as data (never evaluated or executed).
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

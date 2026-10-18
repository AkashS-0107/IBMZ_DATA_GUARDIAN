import React, { useState } from "react";
import { BarChart3, Play, AlertTriangle, RefreshCw } from "lucide-react";
import { api } from "../../api/client";
import { EvaluationMetricsResponse, LiveBenchmarkResponse } from "../../api/types";

interface ModelBenchmarkViewProps {
  metrics: EvaluationMetricsResponse | null;
  onRefreshMetrics: () => void;
}

export const ModelBenchmarkView: React.FC<ModelBenchmarkViewProps> = ({
  metrics,
  onRefreshMetrics,
}) => {
  const [activeTab, setActiveTab] = useState<"stored" | "live">("stored");
  const [liveResult, setLiveResult] = useState<LiveBenchmarkResponse | null>(null);
  const [isRunningLive, setIsRunningLive] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);

  const handleRunLiveBenchmark = async () => {
    setIsRunningLive(true);
    setLiveError(null);
    try {
      const result = await api.runLiveBenchmark();
      setLiveResult(result);
    } catch (err: any) {
      setLiveError(err.message || "Failed to execute live benchmark.");
    } finally {
      setIsRunningLive(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header card */}
      <div className="guardian-card p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-sky-400" />
              <h2 className="text-base font-bold text-slate-100">Dataset & Model Benchmark Evaluation</h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Strictly reflects verified local artifacts and synthetic test fixtures without synthetic inflation.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onRefreshMetrics}
              title="Reload evaluation metrics"
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setActiveTab("stored")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeTab === "stored"
                  ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                  : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              📊 Stored Artifact Report
            </button>

            <button
              onClick={() => setActiveTab("live")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeTab === "live"
                  ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                  : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              ⚡ Live Fixture Evaluation
            </button>
          </div>
        </div>
      </div>

      {/* Tab 1: Stored Report */}
      {activeTab === "stored" && (
        <div className="space-y-4">
          {!metrics || !metrics.available ? (
            <div className="guardian-card p-6 text-center">
              <AlertTriangle className="h-8 w-8 text-amber-400 mx-auto mb-2" />
              <h3 className="text-sm font-semibold text-slate-200">Evaluation Report Artifact Missing</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                {metrics?.status_message ||
                  "models/pii_ner/evaluation_report.json could not be loaded. Run python training/evaluate_model.py to generate."}
              </p>
            </div>
          ) : (
            <>
              {/* Manifest Metadata */}
              <div className="guardian-card p-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div>
                    <span className="text-slate-400">Architecture:</span>
                    <div className="font-semibold text-slate-200">spaCy English Blank (NER)</div>
                  </div>
                  <div>
                    <span className="text-slate-400">Dataset Source:</span>
                    <div className="font-semibold text-slate-200">Synthetic Kaggle BIO Schema</div>
                  </div>
                  <div>
                    <span className="text-slate-400">Sample Split:</span>
                    <div className="font-semibold text-slate-200">12 Train / 1 Val / 2 Test</div>
                  </div>
                  <div>
                    <span className="text-slate-400">Matching Policy:</span>
                    <div className="font-semibold text-sky-400 uppercase">{metrics.matching_policy}</div>
                  </div>
                </div>
              </div>

              {/* Comparative Table */}
              <div className="guardian-card overflow-hidden">
                <div className="px-5 py-3 border-b border-slate-800">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Model Architecture Comparison (Held-out Test Records)
                  </h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#0F172A] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-4 font-semibold">Detection Mode</th>
                        <th className="py-2.5 px-4 font-semibold">Precision</th>
                        <th className="py-2.5 px-4 font-semibold">Recall</th>
                        <th className="py-2.5 px-4 font-semibold">Micro F1</th>
                        <th className="py-2.5 px-4 font-semibold">Macro F1</th>
                        <th className="py-2.5 px-4 font-semibold">TP</th>
                        <th className="py-2.5 px-4 font-semibold">FP</th>
                        <th className="py-2.5 px-4 font-semibold">FN</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono">
                      {metrics.ml_alone && (
                        <tr className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-4 font-sans text-slate-300">Mode 1: ML Model Alone</td>
                          <td className="py-2.5 px-4">{(metrics.ml_alone.overall_micro.precision * 100).toFixed(1)}%</td>
                          <td className="py-2.5 px-4">{(metrics.ml_alone.overall_micro.recall * 100).toFixed(1)}%</td>
                          <td className="py-2.5 px-4">{(metrics.ml_alone.overall_micro.f1_score * 100).toFixed(1)}%</td>
                          <td className="py-2.5 px-4">{(metrics.ml_alone.overall_macro_f1 * 100).toFixed(1)}%</td>
                          <td className="py-2.5 px-4 text-emerald-400">{metrics.ml_alone.overall_micro.true_positives}</td>
                          <td className="py-2.5 px-4 text-red-400">{metrics.ml_alone.overall_micro.false_positives}</td>
                          <td className="py-2.5 px-4 text-amber-400">{metrics.ml_alone.overall_micro.false_negatives}</td>
                        </tr>
                      )}
                      {metrics.rules_alone && (
                        <tr className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-4 font-sans text-slate-300">Mode 2: Rules Alone</td>
                          <td className="py-2.5 px-4">{(metrics.rules_alone.overall_micro.precision * 100).toFixed(1)}%</td>
                          <td className="py-2.5 px-4">{(metrics.rules_alone.overall_micro.recall * 100).toFixed(1)}%</td>
                          <td className="py-2.5 px-4 font-bold text-sky-400">
                            {(metrics.rules_alone.overall_micro.f1_score * 100).toFixed(1)}%
                          </td>
                          <td className="py-2.5 px-4">{(metrics.rules_alone.overall_macro_f1 * 100).toFixed(1)}%</td>
                          <td className="py-2.5 px-4 text-emerald-400">{metrics.rules_alone.overall_micro.true_positives}</td>
                          <td className="py-2.5 px-4 text-red-400">{metrics.rules_alone.overall_micro.false_positives}</td>
                          <td className="py-2.5 px-4 text-amber-400">{metrics.rules_alone.overall_micro.false_negatives}</td>
                        </tr>
                      )}
                      {metrics.hybrid && (
                        <tr className="hover:bg-slate-800/40 bg-sky-500/5">
                          <td className="py-2.5 px-4 font-sans font-bold text-sky-300">Mode 3: Combined Hybrid (Active)</td>
                          <td className="py-2.5 px-4 font-bold text-emerald-400">
                            {(metrics.hybrid.overall_micro.precision * 100).toFixed(1)}%
                          </td>
                          <td className="py-2.5 px-4 font-bold text-sky-400">
                            {(metrics.hybrid.overall_micro.recall * 100).toFixed(1)}%
                          </td>
                          <td className="py-2.5 px-4 font-bold text-indigo-400">
                            {(metrics.hybrid.overall_micro.f1_score * 100).toFixed(1)}%
                          </td>
                          <td className="py-2.5 px-4 font-bold text-indigo-400">
                            {(metrics.hybrid.overall_macro_f1 * 100).toFixed(1)}%
                          </td>
                          <td className="py-2.5 px-4 text-emerald-400">{metrics.hybrid.overall_micro.true_positives}</td>
                          <td className="py-2.5 px-4 text-red-400">{metrics.hybrid.overall_micro.false_positives}</td>
                          <td className="py-2.5 px-4 text-amber-400">{metrics.hybrid.overall_micro.false_negatives}</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Per Entity Breakdown for Hybrid */}
              {metrics.hybrid?.per_entity && (
                <div className="guardian-card overflow-hidden">
                  <div className="px-5 py-3 border-b border-slate-800">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Hybrid Per-Entity Breakdown
                    </h3>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-[#0F172A] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-4 font-semibold">Entity Category</th>
                          <th className="py-2.5 px-4 font-semibold">Precision</th>
                          <th className="py-2.5 px-4 font-semibold">Recall</th>
                          <th className="py-2.5 px-4 font-semibold">F1 Score</th>
                          <th className="py-2.5 px-4 font-semibold">TP</th>
                          <th className="py-2.5 px-4 font-semibold">FP</th>
                          <th className="py-2.5 px-4 font-semibold">FN</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 font-mono">
                        {Object.entries(metrics.hybrid.per_entity).map(([entityName, item]) => (
                          <tr key={entityName} className="hover:bg-slate-800/40">
                            <td className="py-2 px-4 font-sans font-medium text-slate-200">{entityName}</td>
                            <td className="py-2 px-4">{(item.precision * 100).toFixed(1)}%</td>
                            <td className="py-2 px-4">{(item.recall * 100).toFixed(1)}%</td>
                            <td className="py-2 px-4 font-bold text-sky-400">{(item.f1_score * 100).toFixed(1)}%</td>
                            <td className="py-2 px-4 text-emerald-400">{item.true_positives}</td>
                            <td className="py-2 px-4 text-red-400">{item.false_positives}</td>
                            <td className="py-2 px-4 text-amber-400">{item.false_negatives}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Tab 2: Live Fixture Evaluation */}
      {activeTab === "live" && (
        <div className="space-y-4">
          <div className="guardian-card p-5">
            <h3 className="text-sm font-bold text-slate-100 mb-1">Execute Live Fixture Benchmark</h3>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Dynamically evaluates the active hybrid detector across verified deterministic test documents in{" "}
              <code>fixtures/synthetic_pii.jsonl</code> and <code>fixtures/synthetic_secrets.jsonl</code>.
            </p>

            <button
              onClick={handleRunLiveBenchmark}
              disabled={isRunningLive}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs shadow-md shadow-sky-600/20 disabled:opacity-50 transition"
            >
              <Play className={`h-4 w-4 ${isRunningLive ? "animate-spin" : ""}`} />
              <span>{isRunningLive ? "Evaluating Fixtures..." : "⚡ Run Live Fixture Benchmark"}</span>
            </button>

            {liveError && (
              <div className="mt-3 p-3 rounded-lg bg-red-950/40 border border-red-500/30 text-red-300 text-xs">
                {liveError}
              </div>
            )}
          </div>

          {liveResult && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="guardian-card p-3 text-center">
                  <div className="text-[10px] text-slate-400 uppercase">Documents Tested</div>
                  <div className="text-lg font-bold text-white mt-1">{liveResult.total_records}</div>
                </div>
                <div className="guardian-card p-3 text-center">
                  <div className="text-[10px] text-slate-400 uppercase">Micro Precision</div>
                  <div className="text-lg font-bold text-emerald-400 mt-1">
                    {(liveResult.micro_precision * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="guardian-card p-3 text-center">
                  <div className="text-[10px] text-slate-400 uppercase">Micro Recall</div>
                  <div className="text-lg font-bold text-sky-400 mt-1">
                    {(liveResult.micro_recall * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="guardian-card p-3 text-center">
                  <div className="text-[10px] text-slate-400 uppercase">Micro F1 Score</div>
                  <div className="text-lg font-bold text-indigo-400 mt-1">
                    {(liveResult.micro_f1 * 100).toFixed(1)}%
                  </div>
                </div>
              </div>

              {/* Per-entity live results */}
              <div className="guardian-card overflow-hidden">
                <div className="px-5 py-3 border-b border-slate-800">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Live Per-Entity Breakdown ({Object.keys(liveResult.per_entity).length} Categories)
                  </h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-[#0F172A] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-4 font-semibold font-sans">Entity Type</th>
                        <th className="py-2.5 px-4 font-semibold">Precision</th>
                        <th className="py-2.5 px-4 font-semibold">Recall</th>
                        <th className="py-2.5 px-4 font-semibold">F1 Score</th>
                        <th className="py-2.5 px-4 font-semibold">TP</th>
                        <th className="py-2.5 px-4 font-semibold">FP</th>
                        <th className="py-2.5 px-4 font-semibold">FN</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {Object.entries(liveResult.per_entity).map(([cat, m]) => (
                        <tr key={cat} className="hover:bg-slate-800/40">
                          <td className="py-2 px-4 font-sans font-medium text-slate-200">{cat}</td>
                          <td className="py-2 px-4">{(m.precision * 100).toFixed(1)}%</td>
                          <td className="py-2 px-4">{(m.recall * 100).toFixed(1)}%</td>
                          <td className="py-2 px-4 text-sky-400 font-bold">{(m.f1_score * 100).toFixed(1)}%</td>
                          <td className="py-2 px-4 text-emerald-400">{m.true_positives}</td>
                          <td className="py-2 px-4 text-red-400">{m.false_positives}</td>
                          <td className="py-2 px-4 text-amber-400">{m.false_negatives}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

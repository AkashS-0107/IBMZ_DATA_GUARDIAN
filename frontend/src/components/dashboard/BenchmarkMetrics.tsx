import React from "react";
import { BarChart3, CheckCircle2 } from "lucide-react";
import { EvaluationMetricsResponse } from "../../api/types";

interface BenchmarkMetricsProps {
  metrics: EvaluationMetricsResponse | null;
}

export const BenchmarkMetrics: React.FC<BenchmarkMetricsProps> = ({ metrics }) => {
  if (!metrics || !metrics.available || !metrics.hybrid) {
    return (
      <div className="flex flex-col items-center justify-center p-6 text-center h-full">
        <BarChart3 className="h-8 w-8 text-slate-500 mb-2" />
        <div className="text-xs font-semibold text-slate-400">Metrics Unavailable</div>
        <p className="text-[11px] text-slate-500 mt-1">Run training evaluation to generate report</p>
      </div>
    );
  }

  const hybrid = metrics.hybrid;
  const micro = hybrid.overall_micro;

  return (
    <div className="p-4 flex flex-col justify-between h-full">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Verified Benchmark Scores
        </span>
        <span className="text-[10px] px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30">
          Exact-Span
        </span>
      </div>

      <div className="grid grid-cols-3 gap-2 my-2 text-center">
        <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Precision</div>
          <div className="text-sm font-bold text-emerald-400">
            {(micro.precision * 100).toFixed(1)}%
          </div>
        </div>

        <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Recall</div>
          <div className="text-sm font-bold text-sky-400">
            {(micro.recall * 100).toFixed(1)}%
          </div>
        </div>

        <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Micro F1</div>
          <div className="text-sm font-bold text-indigo-400">
            {(micro.f1_score * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800 flex items-center justify-between">
        <span className="flex items-center gap-1">
          <CheckCircle2 className="h-3 w-3 text-emerald-400" />
          <span>Held-Out Test Records ({metrics.total_test_records || 2})</span>
        </span>
        <span>Macro F1: {(hybrid.overall_macro_f1 * 100).toFixed(1)}%</span>
      </div>
    </div>
  );
};

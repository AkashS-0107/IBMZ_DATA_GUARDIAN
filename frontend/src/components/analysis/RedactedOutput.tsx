import React, { useState } from "react";
import { Check, Copy, Download, FileCode, Lock } from "lucide-react";
import { RedactionSummary } from "../../api/types";

interface RedactedOutputProps {
  redaction: RedactionSummary;
}

export const RedactedOutput: React.FC<RedactedOutputProps> = ({ redaction }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(redaction.masked_text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      const el = document.createElement("textarea");
      el.value = redaction.masked_text;
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    const blob = new Blob([redaction.masked_text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sanitized_prompt_${redaction.session_id.slice(-6)}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="guardian-card p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <FileCode className="h-4 w-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            3. Sanitized Prompt (Safe for External AI)
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            {redaction.placeholders_count} Tokens Masked
          </span>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
            title="Copy sanitized prompt to clipboard"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copied ? "Copied!" : "Copy"}</span>
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
            title="Download sanitized text file"
          >
            <Download className="h-3.5 w-3.5 text-sky-400" />
            <span>Download .txt</span>
          </button>
        </div>
      </div>

      <div className="relative">
        <pre className="w-full bg-[#0F172A] border border-slate-800 rounded-lg p-3.5 text-xs text-slate-200 font-mono overflow-x-auto whitespace-pre-wrap select-all">
          {redaction.masked_text}
        </pre>
      </div>

      <div className="mt-3 p-3 rounded-lg bg-sky-950/30 border border-sky-500/30 text-sky-300 text-xs flex items-start gap-2.5">
        <Lock className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold">Zero Automated External Transmission:</span> Sensitive
          values were replaced locally with typed placeholders (e.g. <code>[EMAIL_1]</code>, <code>[API_KEY_1]</code>).
          You retain complete manual control over where this sanitized text is forwarded. Placeholders remain recoverable
          only within your isolated in-memory session.
        </div>
      </div>
    </div>
  );
};

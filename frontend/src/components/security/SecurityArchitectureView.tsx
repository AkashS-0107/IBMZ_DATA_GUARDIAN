import React from "react";
import { ShieldCheck, Lock, AlertTriangle, Database, EyeOff } from "lucide-react";

export const SecurityArchitectureView: React.FC = () => {
  return (
    <div className="space-y-4">
      <div className="guardian-card p-5">
        <div className="flex items-center gap-2 mb-2">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          <h2 className="text-base font-bold text-slate-100">
            Security Architecture & Cryptographic Vault Boundaries
          </h2>
        </div>
        <p className="text-xs text-slate-400">
          AI Data Leak Guardian is designed for the IBM Z Hackathon Challenge:{" "}
          <span className="text-sky-400 font-medium">“AI Secured: Innovation Without Exposure”</span>.
          All sensitive data processing occurs within strict privacy-preserving boundaries.
        </p>
      </div>

      {/* Security Pillars Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="guardian-card p-4 space-y-2">
          <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs">
            <Lock className="h-4 w-4" />
            <span>1. Zero External AI Transmission</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            The system performs local inspection and redaction before prompts leave the trust boundary.
            No automated requests are made to third-party LLMs or cloud endpoints without manual operator oversight.
          </p>
        </div>

        <div className="guardian-card p-4 space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs">
            <Database className="h-4 w-4" />
            <span>2. In-Memory Session Isolation</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Sensitive raw values are stored strictly in Python process RAM inside isolated session vaults.
            Values are never persisted to disk, databases, browser localStorage, or diagnostic logs.
          </p>
        </div>

        <div className="guardian-card p-4 space-y-2">
          <div className="flex items-center gap-2 text-violet-400 font-semibold text-xs">
            <EyeOff className="h-4 w-4" />
            <span>3. Non-Sensitive Audit Logging</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Serialized findings, UI tables, and audit logs record only abstract entity types, rule IDs,
            and character spans. Zero raw credentials or plaintext tokens are exposed.
          </p>
        </div>
      </div>

      {/* Data Flow Diagram */}
      <div className="guardian-card p-5 space-y-3">
        <h3 className="text-sm font-bold text-slate-100">End-to-End Pipeline Data Flow</h3>
        <div className="p-4 rounded-lg bg-[#0F172A] border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
          <pre>{`[1. User Input Payload]
          │
          ▼
[2. Unified Hybrid Detector]
    ├── SecretDetector (Passwords, DB URIs, API Keys, Private Keys, Cloud Tokens)
    ├── PIIDetector (RFC 5322 Email, E.164 Phone, IPv4/v6, SSN, Context Names)
    ├── MLPIIDetector (spaCy English NER Context Model)
    └── EntropyDetector (Shannon H ≥ 3.6 bits/char)
          │
          ▼
[3. Deterministic Conflict Resolution] (Severity Rank > Source Priority > Span Length)
          │
          ▼
[4. Deterministic 4-Tier Risk Engine] (Critical, High, Medium, Low)
          │
          ▼
[5. Reversible Right-to-Left Redactor]
    └── [In-Memory Vault: session_id ──> { "[API_KEY_1]": "sk_live_..." }]
          │
          ▼
[6. Sanitized Prompt Generated] (Forwarded to downstream AI safely)
          │
          ▼
[7. Downstream AI Completion] (Referencing [API_KEY_1])
          │
          ▼
[8. Local Placeholder Restoration] (Safely decoded in-memory; foreign tokens preserved)`}</pre>
        </div>
      </div>

      {/* Defense-in-Depth Prototype Disclaimer */}
      <div className="guardian-card p-4 border-amber-500/30 bg-amber-950/20 text-xs text-amber-200 flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-bold">Defense-in-Depth Prototype Disclaimer:</div>
          <p className="leading-relaxed">
            AI Data Leak Guardian is a privacy-enhancing security prototype designed for prompt screening.
            In-memory dictionary mappings are not an enterprise Hardware Security Module (HSM).
            It should be deployed alongside comprehensive network egress filtering and enterprise secrets management.
          </p>
        </div>
      </div>
    </div>
  );
};

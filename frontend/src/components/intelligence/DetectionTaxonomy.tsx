import React, { useState } from "react";
import { BookOpen, Key, Shield, Hash, Cpu } from "lucide-react";

export const DetectionTaxonomy: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"pii" | "secrets" | "entropy" | "ml">("pii");

  const piiRules = [
    {
      type: "EMAIL",
      name: "RFC 5322 Email Pattern",
      id: "regex:email_rfc5322",
      severity: "Medium",
      pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
      description: "Standard RFC 5322 compliant email detection across modern TLDs.",
    },
    {
      type: "PHONE",
      name: "International Phone (E.164)",
      id: "regex:phone_e164",
      severity: "High",
      pattern: "(?:(?:\\+|00)\\d{1,3})?... (7-15 clean digits)",
      description: "Validates 7 to 15 digits according to E.164 format with lookbehind/lookahead guards to prevent hex collision.",
    },
    {
      type: "IP_ADDRESS",
      name: "IPv4 & IPv6 Addresses",
      id: "regex:ipv4_octet / regex:ipv6_colon",
      severity: "Medium",
      pattern: "Octet-validated IPv4 (0-255) and RFC IPv6 colon notation",
      description: "Validated IP address regexes with ipaddress standard library parsing.",
    },
    {
      type: "PERSONAL_URL",
      name: "Personal Profile URLs",
      id: "regex:personal_profile_url",
      severity: "Low",
      pattern: "linkedin.com/in/* | github.com/* | twitter.com/* | x.com/* | gitlab.com/*",
      description: "Detects personal profile URLs while excluding standard documentation or generic repository links.",
    },
    {
      type: "ID_NUMBER",
      name: "Government ID / US SSN",
      id: "regex:ssn_formatted",
      severity: "High",
      pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b",
      description: "Standard 3-2-4 digit identity format presenting immediate identity theft risk.",
    },
    {
      type: "NAME",
      name: "Contextual Name Marker",
      id: "context:name_honorific",
      severity: "Medium",
      pattern: "(?:Name|Student|Author|Employee|Candidate|Dr.|Mr.|Ms.|Prof.)[: ]+([A-Z][a-z]+...)",
      description: "Context-aware heuristic identifying human person names when preceded by professional or relationship markers.",
    },
  ];

  const secretRules = [
    {
      type: "PASSWORD",
      name: "Password Assignments",
      id: "secret:password_assignment",
      severity: "Critical",
      pattern: "(?:password|passwd|pwd|pass|secret_key|api_secret)\\s*[:=]\\s*['\"]?...['\"]?",
      description: "Captures explicit quoted or unquoted password assignments in scripts and config files.",
    },
    {
      type: "BEARER_TOKEN",
      name: "HTTP Bearer Auth Headers",
      id: "secret:bearer_token_header",
      severity: "Critical",
      pattern: "\\bBearer\\s+([A-Za-z0-9_\\-\\.]{16,})\\b",
      description: "Standard authorization header bearer tokens with minimum 16-character length validation.",
    },
    {
      type: "API_KEY",
      name: "Generic API Key & Secret Tokens",
      id: "secret:api_key_assignment",
      severity: "Critical",
      pattern: "(?:api_key|apikey|access_token|client_secret)\\s*[:=]\\s*['\"]?...['\"]?",
      description: "Variable assignments for API keys and client credentials across programming environments.",
    },
    {
      type: "DB_CREDENTIAL",
      name: "Database Connection URIs",
      id: "secret:db_connection_uri",
      severity: "Critical",
      pattern: "\\b(?:postgres(?:ql)?|mysql|mongodb|mssql|redis|cockroachdb)://[^:\\s]+:[^@\\s]+@...\\b",
      description: "Full database connection strings with embedded plaintext username and password credentials.",
    },
    {
      type: "PRIVATE_KEY",
      name: "PEM Cryptographic Private Keys",
      id: "secret:private_key_pem",
      severity: "Critical",
      pattern: "-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\\s\\S]*?-----END ... PRIVATE KEY-----",
      description: "Complete RSA, DSA, EC, OPENSSH, and PGP cryptographic private key blocks.",
    },
    {
      type: "CLOUD_CREDENTIAL",
      name: "AWS, GitHub & Slack Tokens",
      id: "secret:aws_access_key / secret:github_personal_token / secret:slack_token",
      severity: "Critical",
      pattern: "AKIA/ASIA[A-Z0-9]{16} | gh[pousr]_[A-Za-z0-9_]{36,255} | xox[baprs]-[0-9A-Za-z]{10,48}",
      description: "Provider-specific deterministic signature tokens for major cloud and developer APIs.",
    },
  ];

  return (
    <div className="space-y-4">
      <div className="guardian-card p-5">
        <div className="flex items-center gap-2 mb-2">
          <BookOpen className="h-5 w-5 text-sky-400" />
          <h2 className="text-base font-bold text-slate-100">Detection Engine Taxonomy & Rule Reference</h2>
        </div>
        <p className="text-xs text-slate-400">
          AI Data Leak Guardian employs a unified hybrid detection engine coordinating deterministic regex rules,
          Shannon entropy heuristics, and a contextual spaCy NER model with deterministic conflict resolution.
        </p>

        {/* Taxonomy Tabs */}
        <div className="flex flex-wrap gap-2 mt-4 pt-3 border-t border-slate-800">
          <button
            onClick={() => setActiveTab("pii")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === "pii"
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                : "text-slate-400 hover:bg-slate-800/80"
            }`}
          >
            <Shield className="h-3.5 w-3.5" />
            <span>PII Rules (6)</span>
          </button>

          <button
            onClick={() => setActiveTab("secrets")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === "secrets"
                ? "bg-red-500/20 text-red-300 border border-red-500/40"
                : "text-slate-400 hover:bg-slate-800/80"
            }`}
          >
            <Key className="h-3.5 w-3.5" />
            <span>Secret & Credential Rules (6)</span>
          </button>

          <button
            onClick={() => setActiveTab("entropy")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === "entropy"
                ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                : "text-slate-400 hover:bg-slate-800/80"
            }`}
          >
            <Hash className="h-3.5 w-3.5" />
            <span>Shannon Entropy Heuristics</span>
          </button>

          <button
            onClick={() => setActiveTab("ml")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === "ml"
                ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/40"
                : "text-slate-400 hover:bg-slate-800/80"
            }`}
          >
            <Cpu className="h-3.5 w-3.5" />
            <span>spaCy NER Context Model</span>
          </button>
        </div>
      </div>

      {/* Tab 1: PII */}
      {activeTab === "pii" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {piiRules.map((rule) => (
            <div key={rule.id} className="guardian-card p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm text-slate-100">{rule.name}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/30">
                    {rule.severity}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-sky-300 mb-2">{rule.id}</div>
                <p className="text-xs text-slate-300 leading-relaxed">{rule.description}</p>
              </div>
              <div className="mt-3 pt-2 border-t border-slate-800 font-mono text-[10px] text-slate-500 truncate">
                Pattern: {rule.pattern}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: Secrets */}
      {activeTab === "secrets" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {secretRules.map((rule) => (
            <div key={rule.id} className="guardian-card p-4 flex flex-col justify-between border-red-500/20">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-sm text-slate-100">{rule.name}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
                    {rule.severity}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-red-300 mb-2">{rule.id}</div>
                <p className="text-xs text-slate-300 leading-relaxed">{rule.description}</p>
              </div>
              <div className="mt-3 pt-2 border-t border-slate-800 font-mono text-[10px] text-slate-500 truncate">
                Pattern: {rule.pattern}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Entropy */}
      {activeTab === "entropy" && (
        <div className="guardian-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100">Shannon Entropy Heuristic Engine</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Detects candidate high-entropy secret tokens (such as raw cryptographic salts, random API keys, and custom session tokens)
            by calculating information entropy in bits per character.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Entropy Threshold</div>
              <div className="text-lg font-bold text-amber-400 mt-1">H ≥ 3.60 bits/char</div>
              <p className="text-[11px] text-slate-400 mt-1">Calculated via H(X) = -Σ p(x) log₂(p(x))</p>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Length Constraints</div>
              <div className="text-lg font-bold text-sky-400 mt-1">16 to 256 characters</div>
              <p className="text-[11px] text-slate-400 mt-1">Bound by non-alphanumeric token delimiters</p>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Diversity Guard</div>
              <div className="text-lg font-bold text-emerald-400 mt-1">≥ 2 Char Classes</div>
              <p className="text-[11px] text-slate-400 mt-1">Unique ratio ≥ 0.40, excluding English dictionary words</p>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: ML */}
      {activeTab === "ml" && (
        <div className="guardian-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100">spaCy English Named Entity Recognition (NER)</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Trained on synthetic Kaggle PII competition data formatted according to character offset boundaries.
            Specialized for recognizing students, candidate names, and personal identifiers that do not follow rigid regular expressions.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
              <div className="font-semibold text-sky-300">Deterministic Conflict Resolution:</div>
              <div className="text-slate-300">
                1. <b>Severity Rank:</b> Critical secrets strictly supersede lower-tier PII.<br />
                2. <b>Source Precedence:</b> Regex/Secret Rules &gt; Context Rules &gt; spaCy ML &gt; Entropy.<br />
                3. <b>Span Length:</b> Longer character span breaks remaining ties.
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
              <div className="font-semibold text-emerald-300">Safe Fallback Guarantee:</div>
              <div className="text-slate-300">
                If the ML model directory is absent, corrupted, or disabled during startup, the detector catches the error safely
                and seamlessly operates in <b>Rules-Only Mode</b> without crashing or weakening password/credential detection.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

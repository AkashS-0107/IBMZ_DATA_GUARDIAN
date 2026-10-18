/**
 * TypeScript Data Models matching Python backend schemas in models.py and server.py.
 */

export type Severity = "Low" | "Medium" | "High" | "Critical";

export type EntityType =
  | "EMAIL"
  | "PHONE"
  | "NAME"
  | "IP_ADDRESS"
  | "PERSONAL_URL"
  | "ID_NUMBER"
  | "USERNAME"
  | "STREET_ADDRESS"
  | "PASSWORD"
  | "API_KEY"
  | "BEARER_TOKEN"
  | "DB_CREDENTIAL"
  | "PRIVATE_KEY"
  | "CLOUD_CREDENTIAL"
  | "HIGH_ENTROPY_SECRET";

export interface SystemStatus {
  backend_status: string;
  rules_active: boolean;
  ml_available: boolean;
  ml_model_name: string | null;
  active_vault_sessions: number;
  platform: string;
  python_version: string;
}

export interface Finding {
  entity_type: EntityType | string;
  start: number;
  end: number;
  span_length: number;
  severity: Severity;
  rule_id: string;
  confidence: number;
  description: string;
  metadata?: Record<string, unknown>;
}

export interface RiskSummary {
  risk_level: Severity;
  reasons: string[];
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface RedactionSummary {
  session_id: string;
  masked_text: string;
  placeholders_count: number;
  unique_placeholders: number;
  findings_redacted: number;
}

export interface AnalyzeResponse {
  session_id: string;
  findings: Finding[];
  risk: RiskSummary;
  redaction: RedactionSummary;
}

export interface RestoreResponse {
  session_id: string;
  restored_text: string;
  restored_placeholders: string[];
  unrestored_placeholders: string[];
  is_fully_restored: boolean;
}

export interface SessionResetResponse {
  session_id: string;
  cleared: boolean;
  active_placeholder_count: number;
}

export interface PresetItem {
  id: string;
  title: string;
  content: string;
}

export interface PresetsResponse {
  presets: PresetItem[];
}

export interface MetricItem {
  category: string;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
}

export interface EvaluationMetricsResponse {
  available: boolean;
  status_message: string;
  test_dataset?: string | null;
  total_test_records?: number | null;
  matching_policy?: string | null;
  ml_alone?: {
    overall_micro: MetricItem;
    overall_macro_f1: number;
    per_entity: Record<string, MetricItem>;
  } | null;
  rules_alone?: {
    overall_micro: MetricItem;
    overall_macro_f1: number;
    per_entity: Record<string, MetricItem>;
  } | null;
  hybrid?: {
    overall_micro: MetricItem;
    overall_macro_f1: number;
    per_entity: Record<string, MetricItem>;
  } | null;
  manifest?: Record<string, unknown> | null;
}

export interface LiveBenchmarkResponse {
  total_records: number;
  matching_policy: string;
  micro_precision: number;
  micro_recall: number;
  micro_f1: number;
  macro_f1: number;
  per_entity: Record<string, MetricItem>;
}

export interface SafeActivityEvent {
  id: string;
  timestamp: string;
  action: string;
  risk_level: string;
  entity_counts: string;
  status: string;
}

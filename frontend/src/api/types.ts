// These types mirror the FastAPI response models (backend/app/schemas/).
// If the backend changes a field, `npm run typecheck` shows every place that breaks.

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved" | "false_positive";
export type Role = "viewer" | "analyst" | "admin";

export interface User {
  id: number;
  email: string;
  role: Role;
  created_at: string;
}

export interface Alert {
  id: number;
  rule_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  anomaly_score: number | null;
  status: AlertStatus;
  source_ip: string | null;
  username: string | null;
  created_at: string;
  acknowledged_at: string | null;
  evidence_count: number;
}

export interface AlertPage {
  items: Alert[];
  total: number;
  limit: number;
  offset: number;
}

export interface SecurityEvent {
  id: number;
  source: string;
  event_type: string;
  outcome: string;
  timestamp: string;
  source_ip: string | null;
  username: string | null;
  attributes: Record<string, unknown>;
}

export interface Evidence {
  reason: string;
  event: SecurityEvent;
}

export interface Note {
  id: number;
  author_id: number | null;
  author_email: string | null;
  notes: string;
  updated_at: string;
}

export interface Explanation {
  summary: string;
  why_flagged: string[];
  benign_possibilities: string[];
  investigation_steps: string[];
  uncertainty: string;
  source: "llm" | "fallback";
  model_id: string | null;
  generated_at: string;
  fallback_reason: string | null;
  disclaimer: string;
}

export interface AlertDetail extends Alert {
  explanation: Explanation | null;
  evidence: Evidence[];
  investigation_notes: Note[];
}

export interface AlertSummary {
  total_alerts: number;
  by_status: Partial<Record<AlertStatus, number>>;
  open_by_severity: Partial<Record<Severity, number>>;
  top_source_ips: { source_ip: string; alerts: number }[];
  mean_time_to_acknowledge_seconds: number | null;
}

export interface AnalysisResult {
  events_scanned: number;
  findings: number;
  alerts_created: number;
  window_start: string;
  window_end: string;
  anomaly_model: string | null;
}

export interface AlertFilters {
  status?: AlertStatus;
  severity?: Severity;
  rule_id?: string;
  limit?: number;
  offset?: number;
}

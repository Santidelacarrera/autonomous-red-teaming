export type ApiRole = "viewer" | "operator" | "admin";

export interface AuthenticationContext {
  method: "development" | "oidc";
  strength: "standard" | "mfa";
  authenticated_at: string;
  mfa_satisfied: boolean;
}

export interface Identity {
  subject: string;
  issuer: string;
  roles: ApiRole[];
  permissions: string[];
  authentication: AuthenticationContext;
  token_id: string | null;
  session_id: string | null;
}

export interface SecurityAuditEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  subject: string | null;
  issuer: string | null;
  request_id: string;
  run_id: string | null;
  source: string;
  result: string;
}

export interface SecurityStatus {
  environment: string;
  authentication_provider: string;
  mfa_required_for_sensitive_actions: boolean;
  rate_limiting: string;
  audit_logging: string;
  cors_origins_configured: number;
  recent_events: SecurityAuditEvent[];
  metrics: Record<string, number>;
}

export type SimulationStatus = "created" | "running" | "waiting_approval" | "resuming" | "succeeded" | "completed" | "failed" | "rejected" | "cancelled";

export interface SimulationRun {
  run_id: string;
  created_at: string;
  updated_at: string;
  status: SimulationStatus;
  scenario_id: string;
  graph_version: string;
  workflow_version: string;
  created_by: string;
  request_id: string | null;
  trace_id: string | null;
  risk_before: number | null;
  risk_after: number | null;
  blast_radius_before: number | null;
  blast_radius_after: number | null;
  approval_status: "pending" | "approved" | "rejected";
  approval_timestamp: string | null;
  approval_actor: string | null;
  approval_reason: string | null;
  review_ready: boolean;
  verification_status: "verified" | "partially_verified" | "failed" | "not_run";
  artifacts: string[];
  error_code: string | null;
  cancellation_requested: boolean;
  cancellation_requested_at: string | null;
  cancellation_actor: string | null;
  created?: boolean;
}

export interface SimulationLifecycleEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  status: string;
}

export interface ApiEnvelopeError {
  error: { code: string; message: string; request_id: string };
}

export interface Page<T> { items: T[]; limit: number; offset: number; }

export interface Scenario { scenario_id: string; }

export interface SimulationReview {
  run_id: string;
  generated_at: string;
  risk: { score: number };
  remediation: {
    action: string;
    relationship_type: string;
    reason: string;
    expected_risk_reduction: number;
  };
  remediation_artifact: {
    remediation_kind: string;
    file_path: string;
    content: string;
    summary: string;
    idempotency_key: string;
    content_sha256: string;
  };
  verification_preview: {
    status: "verified" | "partially_verified" | "failed" | "not_run";
    paths_removed: number;
    remaining_paths: number;
    risk_before: number;
    risk_after: number;
    risk_reduction: number;
  };
  automated_preapproval: {
    status: "recommended_for_human_approval" | "blocked";
    evaluated_at: string;
    checks: Record<string, boolean>;
    summary: string;
    requires_human_approval: true;
  };
}

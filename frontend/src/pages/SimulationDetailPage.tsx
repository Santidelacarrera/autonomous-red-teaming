import { useCallback, useEffect, useState } from "react";
import type { SimulationApi } from "../api/simulations";
import type {
  SimulationLifecycleEvent,
  SimulationReview,
  SimulationRun,
  SimulationStatus,
} from "../api/types";
import { Panel } from "../components/Panel";
import { ResultPanel, type ResultSection } from "../components/ResultPanel";
import { RiskCard } from "../components/RiskCard";
import { ErrorState, LoadingState } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { formatTimestamp } from "../utils/format";
import {
  isSuccessfulSimulation,
  shouldPollSimulation,
  shouldRetryPolling,
} from "./simulationPolling";

type DetailTab = "overview" | "risk" | ResultSection | "approval";

const tabs: ReadonlyArray<{ readonly key: DetailTab; readonly label: string }> = [
  { key: "overview", label: "Overview" },
  { key: "risk", label: "Risk" },
  { key: "attack-paths", label: "Attack paths" },
  { key: "blast-radius", label: "Blast radius" },
  { key: "remediations", label: "Remediations" },
  { key: "approval", label: "Approval" },
  { key: "verification", label: "Verification" },
  { key: "report", label: "Report" },
];

interface SimulationDetailProps {
  readonly api: SimulationApi;
  readonly runId: string;
  readonly canApprove: boolean;
  readonly canCancel?: boolean;
  readonly canReadAudit?: boolean;
  readonly onBack: () => void;
}

export function SimulationDetailPage({
  api,
  runId,
  canApprove,
  canCancel = false,
  canReadAudit = false,
  onBack,
}: SimulationDetailProps) {
  const [run, setRun] = useState<SimulationRun | null>(null);
  const [risk, setRisk] = useState<{
    risk_before: number | null;
    risk_after: number | null;
    risk_delta: number | null;
  } | null>(null);
  const [events, setEvents] = useState<SimulationLifecycleEvent[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [tab, setTab] = useState<DetailTab>("overview");

  const refresh = useCallback(async (): Promise<SimulationRun> => {
    try {
      const runValue = await api.get(runId);
      setRun(runValue);
      setRisk(isSuccessfulSimulation(runValue.status) ? await api.risk(runId) : null);
      if (canReadAudit) setEvents((await api.events(runId)).items);
      setError(null);
      return runValue;
    } catch (reason: unknown) {
      setError(reason);
      throw reason;
    }
  }, [api, canReadAudit, runId]);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
    let delay = pollInterval();
    const poll = async (): Promise<void> => {
      try {
        const current = await refresh();
        delay = pollInterval();
        if (active && shouldPollSimulation(current.status)) {
          timer = globalThis.setTimeout(() => void poll(), delay);
        }
      } catch (reason: unknown) {
        if (active && shouldRetryPolling(reason)) {
          delay = Math.min(delay * 2, 60_000);
          timer = globalThis.setTimeout(() => void poll(), delay);
        }
      }
    };
    void poll();
    return () => {
      active = false;
      if (timer !== undefined) globalThis.clearTimeout(timer);
    };
  }, [refresh]);

  const decide = async (decision: "approved" | "rejected", reason: string): Promise<void> => {
    setActionError(null);
    try {
      setRun(await api.decide(runId, decision, reason));
    } catch (reason: unknown) {
      setActionError(reason);
    }
  };

  const cancel = async (): Promise<void> => {
    if (!globalThis.confirm("Cancel this simulation cooperatively?")) return;
    setActionError(null);
    try {
      setRun(await api.cancel(runId));
    } catch (reason: unknown) {
      setActionError(reason);
    }
  };

  if (error && !run) {
    return <><button className="back-button" onClick={onBack}>← Simulations</button><ErrorState error={error} /></>;
  }
  if (!run) return <LoadingState />;

  const cancellable = ["created", "running", "waiting_approval", "resuming"].includes(run.status);
  return <>
    <button className="back-button" onClick={onBack}>← Simulations</button>
    <section className="detail-hero">
      <div>
        <span className="eyebrow">SIMULATION RUN</span>
        <h2><code>{run.run_id}</code></h2>
        <p>{run.scenario_id} · created by <code>{run.created_by}</code></p>
      </div>
      <div>
        <StatusBadge status={run.status} />
        {canCancel && cancellable
          ? <button className="danger-button" onClick={() => void cancel()}>Cancel simulation</button>
          : null}
      </div>
    </section>
    {error ? <ErrorState error={error} /> : null}
    {actionError ? <ErrorState error={actionError} /> : null}
    <div className="tabs" role="tablist" aria-label="Simulation detail">
      {tabs.map((item) => <button key={item.key} className={tab === item.key ? "tab active" : "tab"} onClick={() => setTab(item.key)} role="tab" aria-selected={tab === item.key}>{item.label}</button>)}
    </div>
    <Panel>
      {tab === "overview"
        ? <Overview run={run} events={events} />
        : tab === "risk"
          ? <RiskCard before={risk?.risk_before ?? null} after={risk?.risk_after ?? null} />
          : tab === "approval"
            ? <Approval api={api} run={run} canApprove={canApprove} error={actionError} onDecision={decide} />
            : <ResultPanel api={api} runId={runId} section={tab} />}
    </Panel>
  </>;
}

function Overview({
  run,
  events,
}: {
  readonly run: SimulationRun;
  readonly events: readonly SimulationLifecycleEvent[];
}) {
  const lifecycle: readonly SimulationStatus[] = [
    "created",
    "running",
    "waiting_approval",
    "resuming",
    "succeeded",
  ];
  return <div className="overview-grid">
    <div className="lifecycle">
      <span className="eyebrow">LIFECYCLE</span>
      {events.length > 0
        ? events.map((event) => <div key={event.event_id} className="life-step"><i />{event.event_type.replace("simulation.", "")} · {formatTimestamp(event.timestamp)}</div>)
        : lifecycle.map((step) => <div key={step} className={step === run.status ? "life-step current" : "life-step"}><i />{step.replace("_", " ")}</div>)}
    </div>
    <dl className="metadata">
      <div><dt>Scenario</dt><dd>{run.scenario_id}</dd></div>
      <div><dt>Created</dt><dd>{formatTimestamp(run.created_at)}</dd></div>
      <div><dt>Updated</dt><dd>{formatTimestamp(run.updated_at)}</dd></div>
      <div><dt>Graph version</dt><dd><code>{run.graph_version}</code></dd></div>
      <div><dt>Workflow</dt><dd><code>{run.workflow_version}</code></dd></div>
      <div><dt>Verification</dt><dd>{run.verification_status}</dd></div>
      <div><dt>Artifacts</dt><dd>{run.artifacts.length}</dd></div>
      <div><dt>Error code</dt><dd>{run.error_code ?? "None"}</dd></div>
      <div><dt>Cancellation</dt><dd>{run.cancellation_requested ? "Requested" : "Not requested"}</dd></div>
    </dl>
  </div>;
}

function Approval({
  api,
  run,
  canApprove,
  error,
  onDecision,
}: {
  readonly api: SimulationApi;
  readonly run: SimulationRun;
  readonly canApprove: boolean;
  readonly error: unknown;
  readonly onDecision: (decision: "approved" | "rejected", reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [review, setReview] = useState<SimulationReview | null>(null);
  const [reviewError, setReviewError] = useState<unknown>(null);
  const pending = run.status === "waiting_approval" && run.approval_status === "pending";
  useEffect(() => {
    let active = true;
    if (!run.review_ready) return () => { active = false; };
    void api.review(run.run_id)
      .then((value) => {
        if (active) {
          setReview(value);
          setReviewError(null);
        }
      })
      .catch((failure: unknown) => {
        if (active) setReviewError(failure);
      });
    return () => { active = false; };
  }, [api, run.review_ready, run.run_id]);
  const decisionReady = review?.automated_preapproval.status === "recommended_for_human_approval" && reason.trim().length >= 10;
  return <div className="approval">
    <span className="proposal-label">SIMULATED REMEDIATION · HUMAN REVIEW GATE</span>
    <h3>{run.approval_status}</h3>
    <p>Review the generated countermeasure and its simulated effect. Approval cannot apply, deploy, or modify infrastructure.</p>
    {reviewError ? <ErrorState error={reviewError} /> : null}
    {run.review_ready && review === null && !reviewError ? <LoadingState /> : null}
    {review ? <div className="review-package">
      <p><strong>Automated pre-approval: {review.automated_preapproval.status.replaceAll("_", " ")}</strong></p>
      <p>{review.automated_preapproval.summary}</p>
      <dl className="metadata">
        <div><dt>Action</dt><dd>{review.remediation.action}</dd></div>
        <div><dt>Relationship</dt><dd>{review.remediation.relationship_type}</dd></div>
        <div><dt>Risk</dt><dd>{review.verification_preview.risk_before} → {review.verification_preview.risk_after}</dd></div>
        <div><dt>Path result</dt><dd>{review.verification_preview.paths_removed} removed · {review.verification_preview.remaining_paths} remaining</dd></div>
        <div><dt>Candidate file</dt><dd><code>{review.remediation_artifact.file_path}</code></dd></div>
        <div><dt>SHA-256</dt><dd><code>{review.remediation_artifact.content_sha256}</code></dd></div>
      </dl>
      <p>{review.remediation_artifact.summary}</p>
      <pre>{review.remediation_artifact.content}</pre>
    </div> : null}
    {run.approval_timestamp ? <p>Decision recorded {formatTimestamp(run.approval_timestamp)}.</p> : null}
    {run.approval_reason ? <p>Reviewer rationale: {run.approval_reason}</p> : null}
    {error ? <ErrorState error={error} /> : null}
    {pending && canApprove
      ? <>
        <label className="review-reason">Cybersecurity review rationale
          <textarea value={reason} minLength={10} maxLength={512} onChange={(event) => setReason(event.target.value)} placeholder="Explain why this countermeasure should be approved or rejected." />
        </label>
        <div className="decision-actions">
          <button className="primary-button" disabled={!decisionReady} onClick={() => void onDecision("approved", reason.trim())}>Approve simulated workflow</button>
          <button className="danger-button" disabled={!decisionReady} onClick={() => void onDecision("rejected", reason.trim())}>Reject proposal</button>
        </div>
      </>
      : <p className="permission-note">{pending ? "Your verified identity cannot approve this workflow." : "No pending approval is available for this run."}</p>}
  </div>;
}

function pollInterval(): number {
  const configured = Number(import.meta.env.VITE_POLL_INTERVAL_MS ?? 10_000);
  return Number.isFinite(configured) ? Math.max(3_000, configured) : 10_000;
}

import { useCallback, useEffect, useState } from "react";
import type { SimulationApi } from "../api/simulations";
import type { SimulationRun } from "../api/types";
import { Panel } from "../components/Panel";
import { ResultPanel, type ResultSection } from "../components/ResultPanel";
import { RiskCard } from "../components/RiskCard";
import { ErrorState, LoadingState } from "../components/States";
import { StatusBadge } from "../components/StatusBadge";
import { formatTimestamp } from "../utils/format";

type DetailTab = "overview" | "risk" | ResultSection | "approval";
const tabs: ReadonlyArray<{ readonly key: DetailTab; readonly label: string }> = [{ key: "overview", label: "Overview" }, { key: "risk", label: "Risk" }, { key: "attack-paths", label: "Attack paths" }, { key: "blast-radius", label: "Blast radius" }, { key: "remediations", label: "Remediations" }, { key: "approval", label: "Approval" }, { key: "verification", label: "Verification" }, { key: "report", label: "Report" }];

export function SimulationDetailPage({ api, runId, canApprove, onBack }: { readonly api: SimulationApi; readonly runId: string; readonly canApprove: boolean; readonly onBack: () => void }) {
  const [run, setRun] = useState<SimulationRun | null>(null);
  const [risk, setRisk] = useState<{ risk_before: number | null; risk_after: number | null; risk_delta: number | null } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<DetailTab>("overview");
  const [approvalError, setApprovalError] = useState<unknown>(null);
  const refresh = useCallback(async (): Promise<void> => { try { const [runValue, riskValue] = await Promise.all([api.get(runId), api.risk(runId)]); setRun(runValue); setRisk(riskValue); setError(null); } catch (reason: unknown) { setError(reason); } }, [api, runId]);
  useEffect(() => { void Promise.resolve().then(refresh); }, [refresh]);
  const activeStatus = run?.status;
  useEffect(() => { if (activeStatus === undefined || !["created", "running", "waiting_approval"].includes(activeStatus)) return; const timer = globalThis.setInterval(() => void refresh(), pollInterval()); return () => globalThis.clearInterval(timer); }, [activeStatus, refresh]);
  const decide = async (decision: "approved" | "rejected"): Promise<void> => { setApprovalError(null); try { setRun(await api.decide(runId, decision)); } catch (reason: unknown) { setApprovalError(reason); } };
  if (error) return <><button className="back-button" onClick={onBack}>← Simulations</button><ErrorState error={error} /></>;
  if (!run) return <LoadingState />;
  return <><button className="back-button" onClick={onBack}>← Simulations</button><section className="detail-hero"><div><span className="eyebrow">SIMULATION RUN</span><h2><code>{run.run_id}</code></h2><p>{run.scenario_id} · created by <code>{run.created_by}</code></p></div><StatusBadge status={run.status} /></section><div className="tabs" role="tablist" aria-label="Simulation detail">{tabs.map((item) => <button key={item.key} className={tab === item.key ? "tab active" : "tab"} onClick={() => setTab(item.key)} role="tab" aria-selected={tab === item.key}>{item.label}</button>)}</div><Panel>{tab === "overview" ? <Overview run={run} /> : tab === "risk" ? <RiskCard before={risk?.risk_before ?? null} after={risk?.risk_after ?? null} /> : tab === "approval" ? <Approval run={run} canApprove={canApprove} error={approvalError} onDecision={decide} /> : <ResultPanel api={api} runId={runId} section={tab} />}</Panel></>;
}

function Overview({ run }: { readonly run: SimulationRun }) { return <div className="overview-grid"><div className="lifecycle"><span className="eyebrow">LIFECYCLE</span>{["created", "running", "waiting_approval", "completed"].map((step) => <div key={step} className={step === run.status ? "life-step current" : "life-step"}><i />{step.replace("_", " ")}</div>)}</div><dl className="metadata"><div><dt>Scenario</dt><dd>{run.scenario_id}</dd></div><div><dt>Created</dt><dd>{formatTimestamp(run.created_at)}</dd></div><div><dt>Updated</dt><dd>{formatTimestamp(run.updated_at)}</dd></div><div><dt>Graph version</dt><dd><code>{run.graph_version}</code></dd></div><div><dt>Workflow</dt><dd><code>{run.workflow_version}</code></dd></div><div><dt>Verification</dt><dd>{run.verification_status}</dd></div><div><dt>Artifacts</dt><dd>{run.artifacts.length}</dd></div><div><dt>Error code</dt><dd>{run.error_code ?? "None"}</dd></div></dl></div> }
function Approval({ run, canApprove, error, onDecision }: { readonly run: SimulationRun; readonly canApprove: boolean; readonly error: unknown; readonly onDecision: (decision: "approved" | "rejected") => Promise<void> }) { const pending = run.status === "waiting_approval" && run.approval_status === "pending"; return <div className="approval"><span className="proposal-label">SIMULATED REMEDIATION · HUMAN REVIEW GATE</span><h3>{run.approval_status}</h3><p>Approval only controls the simulated workflow. It cannot apply, deploy, or modify infrastructure.</p>{run.approval_timestamp ? <p>Decision recorded {formatTimestamp(run.approval_timestamp)}.</p> : null}{error ? <ErrorState error={error} /> : null}{pending && canApprove ? <div className="decision-actions"><button className="primary-button" onClick={() => void onDecision("approved")}>Approve simulated workflow</button><button className="danger-button" onClick={() => void onDecision("rejected")}>Reject proposal</button></div> : <p className="permission-note">{pending ? "Your verified identity cannot approve this workflow." : "No pending approval is available for this run."}</p>}</div> }
function pollInterval(): number { const configured = Number(import.meta.env.VITE_POLL_INTERVAL_MS ?? 10_000); return Number.isFinite(configured) ? Math.max(3_000, configured) : 10_000; }

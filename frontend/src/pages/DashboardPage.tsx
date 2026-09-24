import type { Page, SimulationRun } from "../api/types";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { MetricCard, Panel } from "../components/Panel";
import { SimulationTable } from "../components/SimulationTable";

export function DashboardPage({ page, loading, error, onSelect, onViewAll, onCreate, canCreate }: { readonly page: Page<SimulationRun> | null; readonly loading: boolean; readonly error: unknown; readonly onSelect: (runId: string) => void; readonly onViewAll: () => void; readonly onCreate: () => void; readonly canCreate: boolean }) {
  const runs = page?.items ?? [];
  const active = runs.filter((run) => ["created", "running", "waiting_approval", "resuming"].includes(run.status)).length;
  const completed = runs.filter((run) => ["succeeded", "completed"].includes(run.status)).length;
  const assessed = runs.filter((run) => run.risk_before !== null).length;
  return <>
    <section className="page-hero"><div><span className="eyebrow">SHADOW ENVIRONMENT · OBSERVABILITY</span><h2>Defensive simulation visibility.</h2><p>Operate within the API-controlled simulation boundary. No infrastructure changes are available from this console.</p></div>{canCreate ? <button className="primary-button" onClick={onCreate}>New simulation <span aria-hidden="true">+</span></button> : null}</section>
    {loading ? <LoadingState /> : error ? <ErrorState error={error} /> : <>
      <div className="metrics-grid"><MetricCard label="Loaded runs" value={runs.length} detail={`Current API page · offset ${page?.offset ?? 0}`} /><MetricCard label="Active" value={active} detail="Created, running or awaiting approval" accent="violet" /><MetricCard label="Risk assessed" value={assessed} detail="Runs with API-provided risk" accent="amber" /><MetricCard label="Completed" value={completed} detail="Current API page" accent="green" /></div>
      <Panel title="Recent simulations" eyebrow="LIVE API DATA" className="recent-panel">{runs.length ? <SimulationTable items={runs.slice(0, 6)} onSelect={onSelect} /> : <EmptyState>No simulations have been created through this API yet.</EmptyState>}<div className="panel-footer"><button className="text-button" onClick={onViewAll}>View all simulations →</button></div></Panel>
    </>}
  </>;
}

import type { Page, SimulationRun, SimulationStatus } from "../api/types";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { Panel } from "../components/Panel";
import { SimulationTable } from "../components/SimulationTable";

interface SimulationListPageProps {
  readonly page: Page<SimulationRun> | null;
  readonly status: SimulationStatus | "";
  readonly loading: boolean;
  readonly error: unknown;
  readonly onStatus: (status: SimulationStatus | "") => void;
  readonly onRefresh: () => void;
  readonly onSelect: (runId: string) => void;
  readonly onPageChange: (offset: number) => void;
  readonly onCreate: () => void;
  readonly canCreate: boolean;
}

export function SimulationListPage({ page, status, loading, error, onStatus, onRefresh, onSelect, onPageChange, onCreate, canCreate }: SimulationListPageProps) {
  const canPrevious = (page?.offset ?? 0) > 0;
  const canNext = (page?.items.length ?? 0) === (page?.limit ?? 50);
  return <>
    <section className="page-hero compact"><div><span className="eyebrow">SIMULATION OPERATIONS</span><h2>Simulation inventory</h2><p>Bounded, server-side pagination. Data is never synthesized in the browser.</p></div>{canCreate ? <button className="primary-button" onClick={onCreate}>New simulation <span aria-hidden="true">+</span></button> : null}</section>
    <Panel title="Simulation runs" eyebrow="DURABLE OPERATIONAL STORE">
      <div className="table-tools"><label>Status<select value={status} onChange={(event) => onStatus(event.target.value as SimulationStatus | "")}><option value="">All statuses</option><option value="created">created</option><option value="running">running</option><option value="waiting_approval">waiting approval</option><option value="resuming">resuming</option><option value="succeeded">succeeded</option><option value="completed">completed (legacy)</option><option value="failed">failed</option><option value="rejected">rejected</option><option value="cancelled">cancelled</option></select></label><button className="secondary-button" onClick={onRefresh}>Refresh</button></div>
      {loading ? <LoadingState /> : error ? <ErrorState error={error} /> : page?.items.length ? <SimulationTable items={page.items} onSelect={onSelect} /> : <EmptyState>No runs match the current API filter.</EmptyState>}
      <footer className="pagination"><button className="secondary-button" disabled={!canPrevious} onClick={() => onPageChange(Math.max(0, (page?.offset ?? 0) - (page?.limit ?? 50)))}>Previous</button><span>Offset <code>{page?.offset ?? 0}</code> · page size <code>{page?.limit ?? 50}</code></span><button className="secondary-button" disabled={!canNext} onClick={() => onPageChange((page?.offset ?? 0) + (page?.limit ?? 50))}>Next</button></footer>
    </Panel>
  </>;
}

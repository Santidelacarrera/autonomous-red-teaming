import type { SimulationRun } from "../api/types";
import { formatRisk, formatTimestamp, shortId } from "../utils/format";
import { StatusBadge } from "./StatusBadge";

export function SimulationTable({ items, onSelect }: { readonly items: readonly SimulationRun[]; readonly onSelect: (runId: string) => void }) {
  return <div className="table-wrap"><table><thead><tr><th>Status</th><th>Run ID</th><th>Scenario</th><th>Risk</th><th>Created</th><th /></tr></thead><tbody>{items.map((run) => <tr key={run.run_id}><td><StatusBadge status={run.status} /></td><td><code>{shortId(run.run_id)}</code></td><td>{run.scenario_id}</td><td>{formatRisk(run.risk_before)}</td><td><time dateTime={run.created_at}>{formatTimestamp(run.created_at)}</time></td><td><button className="text-button" onClick={() => onSelect(run.run_id)}>Inspect <span aria-hidden="true">→</span></button></td></tr>)}</tbody></table></div>;
}

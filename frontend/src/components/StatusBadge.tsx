import type { SimulationStatus } from "../api/types";

export function StatusBadge({ status }: { status: SimulationStatus }) {
  return <span className={`badge badge-${status}`} aria-label={`Simulation status: ${status}`}>{status.replace("_", " ")}</span>;
}

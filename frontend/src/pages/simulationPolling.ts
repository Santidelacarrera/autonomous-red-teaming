import { ApiClientError } from "../api/client";
import type { SimulationStatus } from "../api/types";

const pollingStatuses: ReadonlySet<SimulationStatus> = new Set(["created", "running", "waiting_approval", "resuming"]);
const successfulStatuses: ReadonlySet<SimulationStatus> = new Set(["succeeded", "completed"]);

export function shouldPollSimulation(status: SimulationStatus): boolean { return pollingStatuses.has(status); }
export function isSuccessfulSimulation(status: SimulationStatus): boolean { return successfulStatuses.has(status); }
export function shouldRetryPolling(error: unknown): boolean {
  return error instanceof ApiClientError && (error.status === 0 || error.status === 429);
}

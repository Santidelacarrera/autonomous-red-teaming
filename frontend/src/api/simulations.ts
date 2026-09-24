import { ApiClient } from "./client";
import type { Identity, Page, Scenario, SecurityStatus, SimulationRun, SimulationStatus } from "./types";

export class SimulationApi {
  constructor(private readonly client: ApiClient) {}

  list(limit = 50, offset = 0, status?: SimulationStatus): Promise<Page<SimulationRun>> {
    const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (status) query.set("status", status);
    return this.client.request(`/api/v1/simulations?${query}`);
  }

  get(runId: string): Promise<SimulationRun> { return this.client.request(`/api/v1/simulations/${runId}`); }
  scenarios(): Promise<{ items: Scenario[] }> { return this.client.request("/api/v1/scenarios"); }
  identity(): Promise<Identity> { return this.client.request("/api/v1/identity"); }
  securityStatus(): Promise<SecurityStatus> { return this.client.request("/api/v1/security/status"); }
  async logout(): Promise<void> { await this.client.request<void>("/api/v1/logout", { method: "POST" }); }
  create(scenarioId: string, idempotencyKey: string): Promise<SimulationRun> {
    return this.client.request("/api/v1/simulations", { method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, body: JSON.stringify({ scenario_id: scenarioId }) });
  }
  decide(runId: string, decision: "approved" | "rejected"): Promise<SimulationRun> {
    return this.client.request(`/api/v1/simulations/${runId}/approval`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision }) });
  }
  risk(runId: string): Promise<{ risk_before: number | null; risk_after: number | null; risk_delta: number | null }> {
    return this.client.request(`/api/v1/simulations/${runId}/risk`);
  }
  result<T>(runId: string, section: "attack-paths" | "blast-radius" | "remediations" | "verification" | "report"): Promise<T> {
    return this.client.request(`/api/v1/simulations/${runId}/${section}`);
  }
}

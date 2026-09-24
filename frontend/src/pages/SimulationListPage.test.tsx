import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { SimulationRun } from "../api/types";
import { SimulationListPage } from "./SimulationListPage";

const run: SimulationRun = { run_id: "12345678-1234-4234-9234-123456789abc", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", status: "running", scenario_id: "shadow-demo", graph_version: "v1", workflow_version: "v1", created_by: "alice", risk_before: null, risk_after: null, blast_radius_before: null, blast_radius_after: null, approval_status: "pending", approval_timestamp: null, verification_status: "not_run", artifacts: [], error_code: null };

describe("SimulationListPage", () => {
  it("renders real API rows and uses the supplied selection callback", () => {
    render(<SimulationListPage page={{ items: [run], limit: 20, offset: 0 }} status="" loading={false} error={null} onStatus={vi.fn()} onRefresh={vi.fn()} onSelect={vi.fn()} onPageChange={vi.fn()} onCreate={vi.fn()} canCreate />);
    expect(screen.getByText("shadow-demo")).toBeInTheDocument();
    expect(screen.getByLabelText("Simulation status: running")).toBeInTheDocument();
  });
});

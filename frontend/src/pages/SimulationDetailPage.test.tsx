import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SimulationApi } from "../api/simulations";
import type { SimulationRun, SimulationStatus } from "../api/types";
import { SimulationDetailPage } from "./SimulationDetailPage";
import { shouldPollSimulation } from "./simulationPolling";

const baseRun: SimulationRun = {
  run_id: "12345678-1234-4234-9234-123456789abc",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  status: "created",
  scenario_id: "shadow-demo",
  graph_version: "shadow-fixture-v1",
  workflow_version: "worker-v1",
  created_by: "alice",
  request_id: "request-1",
  trace_id: null,
  risk_before: null,
  risk_after: null,
  blast_radius_before: null,
  blast_radius_after: null,
  approval_status: "pending",
  approval_timestamp: null,
  approval_actor: null,
  verification_status: "not_run",
  artifacts: [],
  error_code: null,
  cancellation_requested: false,
  cancellation_requested_at: null,
  cancellation_actor: null,
};

function run(status: SimulationStatus, updates: Partial<SimulationRun> = {}): SimulationRun {
  return { ...baseRun, ...updates, status };
}

function apiFor(value: SimulationRun) {
  return {
    get: vi.fn().mockResolvedValue(value),
    risk: vi.fn().mockResolvedValue({ risk_before: 70, risk_after: 0, risk_delta: 70 }),
    decide: vi.fn().mockResolvedValue(run("resuming", { approval_status: "approved" })),
    cancel: vi.fn().mockResolvedValue(run("cancelled", { cancellation_requested: true })),
    events: vi.fn().mockResolvedValue({ items: [] }),
    result: vi.fn().mockResolvedValue({ items: [{ path: "persisted" }] }),
  };
}

afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("SimulationDetailPage durable lifecycle", () => {
  it("polls CREATED, RUNNING, WAITING_APPROVAL and RESUMING only", () => {
    for (const status of ["created", "running", "waiting_approval", "resuming"] as const) expect(shouldPollSimulation(status)).toBe(true);
    for (const status of ["succeeded", "failed", "cancelled", "rejected", "completed"] as const) expect(shouldPollSimulation(status)).toBe(false);
  });

  it("polls an active run and stops after successful terminal state", async () => {
    vi.useFakeTimers();
    const api = apiFor(run("created"));
    api.get.mockResolvedValueOnce(run("created")).mockResolvedValueOnce(run("succeeded"));
    const view = render(<SimulationDetailPage api={api as unknown as SimulationApi} runId={baseRun.run_id} canApprove onBack={vi.fn()} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(api.get).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(api.get).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(api.get).toHaveBeenCalledTimes(2);
    view.unmount();
  });

  it("shows approval controls only for a waiting authorized operator", async () => {
    const api = apiFor(run("waiting_approval"));
    render(<SimulationDetailPage api={api as unknown as SimulationApi} runId={baseRun.run_id} canApprove onBack={vi.fn()} />);
    await screen.findByText(baseRun.run_id);
    fireEvent.click(screen.getByRole("tab", { name: "Approval" }));
    expect(screen.getByRole("button", { name: "Approve simulated workflow" })).toBeInTheDocument();
  });

  it("loads persisted risk and selected result after SUCCEEDED", async () => {
    const api = apiFor(run("succeeded", { verification_status: "verified" }));
    render(<SimulationDetailPage api={api as unknown as SimulationApi} runId={baseRun.run_id} canApprove onBack={vi.fn()} />);
    await waitFor(() => expect(api.risk).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole("tab", { name: "Attack paths" }));
    await waitFor(() => expect(api.result).toHaveBeenCalledWith(baseRun.run_id, "attack-paths"));
    expect(await screen.findByText(/persisted/)).toBeInTheDocument();
  });

  it("renders a safe FAILED state and does not request result data", async () => {
    const api = apiFor(run("failed", { error_code: "WORKFLOW_EXECUTION_FAILED" }));
    render(<SimulationDetailPage api={api as unknown as SimulationApi} runId={baseRun.run_id} canApprove onBack={vi.fn()} />);
    expect(await screen.findByText("WORKFLOW_EXECUTION_FAILED")).toBeInTheDocument();
    expect(api.risk).not.toHaveBeenCalled();
    expect(api.result).not.toHaveBeenCalled();
  });

  it("confirms cooperative cancellation and renders CANCELLED", async () => {
    vi.spyOn(globalThis, "confirm").mockReturnValue(true);
    const api = apiFor(run("running"));
    render(<SimulationDetailPage api={api as unknown as SimulationApi} runId={baseRun.run_id} canApprove canCancel onBack={vi.fn()} />);
    await screen.findByText(baseRun.run_id);
    fireEvent.click(screen.getByRole("button", { name: "Cancel simulation" }));
    await waitFor(() => expect(api.cancel).toHaveBeenCalledWith(baseRun.run_id));
    expect(await screen.findByText("cancelled")).toBeInTheDocument();
  });
});

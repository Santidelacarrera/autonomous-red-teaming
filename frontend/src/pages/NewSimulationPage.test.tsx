import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SimulationApi } from "../api/simulations";
import { NewSimulationPage } from "./NewSimulationPage";

afterEach(cleanup);

describe("NewSimulationPage batches", () => {
  it("submits five independently tracked Shadow simulations", async () => {
    const runId = "12345678-1234-4234-9234-123456789abc";
    const api = {
      scenarios: vi.fn().mockResolvedValue({ items: [{ scenario_id: "shadow-demo" }] }),
      createBatch: vi.fn().mockResolvedValue({
        count: 5,
        items: [{ run_id: runId }],
      }),
    };
    const onCreated = vi.fn();
    render(<NewSimulationPage api={api as unknown as SimulationApi} canCreate onCreated={onCreated} />);

    await screen.findByText("shadow-demo");
    fireEvent.click(screen.getByRole("button", { name: "5 simulations" }));
    fireEvent.click(screen.getByRole("button", { name: "Create 5 simulations" }));

    await waitFor(() => expect(api.createBatch).toHaveBeenCalledWith(
      ["shadow-demo"],
      5,
      expect.any(String),
    ));
    expect(onCreated).toHaveBeenCalledWith(runId);
  });
});

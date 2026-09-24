import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RiskCard } from "./RiskCard";
import { StatusBadge } from "./StatusBadge";

describe("dashboard status components", () => {
  it("renders the persisted simulation status accessibly", () => {
    render(<StatusBadge status="waiting_approval" />);
    expect(screen.getByLabelText("Simulation status: waiting_approval")).toHaveTextContent("waiting approval");
  });

  it("does not manufacture a risk score when the API has no value", () => {
    render(<RiskCard before={null} after={null} />);
    expect(screen.getByText("Not available")).toBeInTheDocument();
  });
});

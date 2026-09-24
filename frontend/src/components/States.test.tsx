import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiClientError } from "../api/client";
import { ErrorState } from "./States";

describe("ErrorState", () => {
  it("explains a pending result without portraying it as data", () => {
    render(<ErrorState error={new ApiClientError("pending", 409, "RUN_CONFLICT", "request-1")} />);
    expect(screen.getByText(/Not available yet/)).toBeInTheDocument();
  });

  it("exposes a safe correlation identifier for API failures", () => {
    render(<ErrorState error={new ApiClientError("denied", 403, "AUTHORIZATION_DENIED", "request-2")} />);
    expect(screen.getByText(/Request ID: request-2/)).toBeInTheDocument();
  });

  it("distinguishes expired authentication and rate limiting", () => {
    const { rerender } = render(<ErrorState error={new ApiClientError("expired", 401, "AUTHENTICATION_REQUIRED", null)} />);
    expect(screen.getByText(/Authentication is required or has expired/)).toBeInTheDocument();
    rerender(<ErrorState error={new ApiClientError("limited", 429, "RATE_LIMIT_EXCEEDED", null)} />);
    expect(screen.getByText(/rate limit exceeded/)).toBeInTheDocument();
  });
});

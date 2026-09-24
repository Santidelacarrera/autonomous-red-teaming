import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import type { Identity } from "../api/types";
import { AuthProvider } from "./AuthProvider";
import { useAuth } from "./useAuth";

const identity: Identity = { subject: "alice", issuer: "art-sim-development", roles: ["operator"], permissions: ["simulation:read", "simulation:create"], authentication: { method: "development", strength: "standard", authenticated_at: "2026-01-01T00:00:00Z", mfa_satisfied: false }, token_id: null, session_id: null };

function Harness() {
  const auth = useAuth();
  if (!auth.authenticated) return <button onClick={() => void auth.loginDevelopment("operator", "alice")}>Login</button>;
  return <><span>{auth.identity?.subject}</span><span>{String(auth.hasPermission("simulation:create"))}</span><button onClick={() => void auth.logout()}>Logout</button></>;
}

describe("AuthProvider", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("protects the application until an identity is authenticated", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Command Center access" })).toBeInTheDocument();
  });

  it("keeps the development token in memory and clears identity on logout", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(identity), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<AuthProvider><Harness /></AuthProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Login" }));
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
    expect(screen.getByText("true")).toBeInTheDocument();
    expect(fetchMock.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer development:operator:alice" }) }));
    fireEvent.click(screen.getByRole("button", { name: "Logout" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Login" })).toBeInTheDocument());
  });
});

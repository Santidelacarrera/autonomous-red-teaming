import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Identity } from "../api/types";
import { DashboardPage } from "../pages/DashboardPage";
import { AppShell } from "./AppShell";

function identity(role: "viewer" | "admin", permissions: string[]): Identity {
  return { subject: `${role}-user`, issuer: "test", roles: [role], permissions, authentication: { method: "development", strength: "standard", authenticated_at: "2026-01-01T00:00:00Z", mfa_satisfied: false }, token_id: null, session_id: null };
}

describe("permission-aware UI", () => {
  it("hides simulation creation when the verified identity lacks permission", () => {
    render(<DashboardPage page={{ items: [], limit: 20, offset: 0 }} loading={false} error={null} onSelect={vi.fn()} onViewAll={vi.fn()} onCreate={vi.fn()} canCreate={false} />);
    expect(screen.queryByRole("button", { name: /New simulation/ })).not.toBeInTheDocument();
  });

  it("shows the security route only to identities with security admin permission", () => {
    const { rerender } = render(<AppShell view="dashboard" apiStatus="online" lastRequestId={null} onNavigate={vi.fn()} identity={identity("viewer", ["simulation:read"])} onLogout={vi.fn()}><span>content</span></AppShell>);
    expect(screen.queryByRole("button", { name: /Security$/ })).not.toBeInTheDocument();
    rerender(<AppShell view="dashboard" apiStatus="online" lastRequestId={null} onNavigate={vi.fn()} identity={identity("admin", ["simulation:read", "security:admin"])} onLogout={vi.fn()}><span>content</span></AppShell>);
    expect(screen.getByRole("button", { name: /Security$/ })).toBeInTheDocument();
  });
});

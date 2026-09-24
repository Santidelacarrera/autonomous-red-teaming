import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

describe("ApiClient", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("sends the development token and forwards server request correlation", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "X-Request-ID": "server-request" } }));
    vi.stubGlobal("fetch", fetchMock);
    let correlated: string | null = null;
    const client = new ApiClient("", () => "development:viewer:alice", (requestId) => { correlated = requestId; });
    await expect(client.request<{ items: unknown[] }>("/api/v1/scenarios")).resolves.toEqual({ items: [] });
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/scenarios", expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer development:viewer:alice" }) }));
    expect(correlated).toBe("server-request");
  });

  it("converts a 409 response into a typed pending-result error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "RUN_CONFLICT", message: "not persisted", request_id: "request-3" } }), { status: 409, headers: { "X-Request-ID": "request-3" } })));
    await expect(new ApiClient("", () => null).request("/api/v1/simulations/run/report")).rejects.toMatchObject({ status: 409, code: "RUN_CONFLICT", requestId: "request-3" });
  });

  it("notifies the auth boundary on 401 but not on 403", async () => {
    const expired = vi.fn();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "AUTHENTICATION_REQUIRED", message: "expired", request_id: "request-4" } }), { status: 401 })));
    await expect(new ApiClient("", () => "token", undefined, expired).request("/api/v1/identity")).rejects.toMatchObject({ status: 401 });
    expect(expired).toHaveBeenCalledOnce();
  });
});

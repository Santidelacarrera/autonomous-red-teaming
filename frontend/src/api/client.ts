import type { ApiEnvelopeError } from "./types";

export class ApiClientError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly requestId: string | null,
  ) {
    super(message);
  }

  get isPendingResult(): boolean { return this.status === 409; }
}

export class ApiClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: () => string | null,
    private readonly onRequestId?: (requestId: string | null) => void,
    private readonly onAuthenticationFailure?: () => void,
  ) {}

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), 10_000);
    const requestId = createRequestId();
    try {
      const token = this.token();
      const response = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          "X-Request-ID": requestId,
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...init.headers,
        },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null) as ApiEnvelopeError | null;
        const responseRequestId = response.headers.get("X-Request-ID") ?? payload?.error?.request_id ?? null;
        this.onRequestId?.(responseRequestId);
        if (response.status === 401) this.onAuthenticationFailure?.();
        throw new ApiClientError(
          payload?.error?.message ?? "The API request could not be completed.",
          response.status,
          payload?.error?.code ?? "API_REQUEST_FAILED",
          responseRequestId,
        );
      }
      this.onRequestId?.(response.headers.get("X-Request-ID"));
      if (response.status === 204) return undefined as T;
      return response.json() as Promise<T>;
    } catch (error: unknown) {
      if (error instanceof ApiClientError) throw error;
      const code = error instanceof DOMException && error.name === "AbortError"
        ? "REQUEST_TIMEOUT"
        : "NETWORK_UNAVAILABLE";
      throw new ApiClientError("The Command Center could not reach the API.", 0, code, null);
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}

function createRequestId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return `ui-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

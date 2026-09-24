import type { ReactNode } from "react";
import { ApiClientError } from "../api/client";

export function LoadingState() { return <p className="state" role="status">Loading simulation data…</p>; }
export function EmptyState({ children }: { children: ReactNode }) { return <p className="state">{children}</p>; }
export function ErrorState({ error }: { error: unknown }) {
  if (error instanceof ApiClientError && error.isPendingResult) return <p className="state pending">Not available yet. The simulation worker has not persisted this result.</p>;
  if (error instanceof ApiClientError && error.status === 401) return <p className="state error">Authentication is required or has expired.{error.requestId ? ` Request ID: ${error.requestId}` : ""}</p>;
  if (error instanceof ApiClientError && error.status === 403) return <p className="state error">You do not have permission to perform this action.{error.requestId ? ` Request ID: ${error.requestId}` : ""}</p>;
  if (error instanceof ApiClientError && error.status === 429) return <p className="state pending">Request rate limit exceeded. Wait before retrying.</p>;
  const requestId = error instanceof ApiClientError ? error.requestId : null;
  return <p className="state error">A safe API error occurred.{requestId ? ` Request ID: ${requestId}` : ""}</p>;
}

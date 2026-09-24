import { useEffect, useState } from "react";
import type { SimulationApi } from "../api/simulations";
import type { SecurityStatus } from "../api/types";
import { ErrorState, LoadingState } from "../components/States";
import { MetricCard, Panel } from "../components/Panel";
import { formatTimestamp } from "../utils/format";

export function SecurityPage({ api }: { readonly api: SimulationApi }) {
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => { let active = true; void api.securityStatus().then((value) => { if (active) setStatus(value); }).catch((reason: unknown) => { if (active) setError(reason); }); return () => { active = false; }; }, [api]);
  if (error) return <ErrorState error={error} />;
  if (!status) return <LoadingState />;
  return <><section className="page-hero compact"><div><span className="eyebrow">ADMINISTRATIVE READ-ONLY VIEW</span><h2>Identity & access security</h2><p>Non-sensitive runtime posture and recent typed security decisions.</p></div></section><div className="metrics-grid"><MetricCard label="Authentication" value={status.authentication_provider.toUpperCase()} detail={status.environment} /><MetricCard label="MFA policy" value={status.mfa_required_for_sensitive_actions ? "REQUIRED" : "OPTIONAL"} detail="Sensitive simulated actions" accent="violet" /><MetricCard label="Rate limiting" value={status.rate_limiting.toUpperCase()} detail="Provider-neutral boundary" accent="amber" /><MetricCard label="Audit" value={status.audit_logging.toUpperCase()} detail="Security events" accent="green" /></div><Panel title="Recent security events" eyebrow="REDACTED · API DATA"><div className="security-events">{status.recent_events.map((event) => <article key={event.event_id}><span className="event-result">{event.result}</span><b>{event.event_type}</b><small>{event.subject ?? "anonymous"} · {formatTimestamp(event.timestamp)}</small><code>{event.request_id}</code></article>)}</div></Panel></>;
}

import { useEffect, useState } from "react";
import type { SimulationApi } from "../api/simulations";
import { ErrorState, LoadingState } from "./States";

export type ResultSection = "attack-paths" | "blast-radius" | "remediations" | "verification" | "report";

export function ResultPanel({ api, runId, section }: { readonly api: SimulationApi; readonly runId: string; readonly section: ResultSection }) {
  const [state, setState] = useState<{ readonly loading: boolean; readonly error: unknown; readonly data: unknown }>({ loading: true, error: null, data: null });
  useEffect(() => {
    let active = true;
    void Promise.resolve().then(async () => {
      if (active) setState({ loading: true, error: null, data: null });
      const data = await api.result<unknown>(runId, section);
      if (active) setState({ loading: false, error: null, data });
    }).catch((error: unknown) => { if (active) setState({ loading: false, error, data: null }); });
    return () => { active = false; };
  }, [api, runId, section]);
  if (state.loading) return <LoadingState />;
  if (state.error) return <ErrorState error={state.error} />;
  return <div className="result-data"><span className={section === "remediations" ? "proposal-label" : "eyebrow"}>{section === "remediations" ? "PROPOSED REMEDIATION · SIMULATION ONLY" : "PERSISTED SIMULATION OUTPUT"}</span><pre>{JSON.stringify(state.data, null, 2)}</pre></div>;
}

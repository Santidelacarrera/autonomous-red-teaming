import { useEffect, useState } from "react";
import type { SimulationApi } from "../api/simulations";
import type { Scenario } from "../api/types";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { Panel } from "../components/Panel";

export function NewSimulationPage({ api, canCreate, onCreated }: { readonly api: SimulationApi; readonly canCreate: boolean; readonly onCreated: (runId: string) => void }) {
  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [selected, setSelected] = useState<string>("");
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);
  useEffect(() => { let active = true; void api.scenarios().then((result) => { if (active) { setScenarios(result.items); setSelected((current) => current || result.items[0]?.scenario_id || ""); } }).catch((reason: unknown) => { if (active) setError(reason); }); return () => { active = false; }; }, [api]);
  const create = async (): Promise<void> => { if (!selected || !canCreate) return; setCreating(true); setError(null); try { const result = await api.create(selected, crypto.randomUUID()); onCreated(result.run_id); } catch (reason: unknown) { setError(reason); } finally { setCreating(false); } };
  return <><section className="page-hero compact"><div><span className="eyebrow">CONTROLLED SCENARIO CATALOG</span><h2>New defensive simulation</h2><p>Only server-configured Shadow scenarios can be requested. Creation queues a simulation record; it does not execute an attack.</p></div></section><Panel title="Select a scenario" eyebrow="API ALLOW-LIST">{error ? <ErrorState error={error} /> : scenarios === null ? <LoadingState /> : scenarios.length === 0 ? <EmptyState>The API has not configured any scenarios.</EmptyState> : <><div className="scenario-grid">{scenarios.map((scenario) => <button key={scenario.scenario_id} className={selected === scenario.scenario_id ? "scenario-card selected" : "scenario-card"} onClick={() => setSelected(scenario.scenario_id)}><span className="scenario-icon">◇</span><b>{scenario.scenario_id}</b><small>Controlled simulation scenario</small></button>)}</div>{!canCreate ? <p className="permission-note">Your verified identity cannot create simulations.</p> : null}<div className="create-bar"><span>Idempotency key is generated per request and is not persisted in the browser.</span><button className="primary-button" disabled={!canCreate || !selected || creating} onClick={() => void create()}>{creating ? "Creating…" : "Create simulation"}</button></div></>}</Panel></>;
}

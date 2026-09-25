import { useEffect, useState } from "react";
import type { SimulationApi } from "../api/simulations";
import type { Scenario } from "../api/types";
import { Panel } from "../components/Panel";
import { EmptyState, ErrorState, LoadingState } from "../components/States";

interface NewSimulationPageProps {
  readonly api: SimulationApi;
  readonly canCreate: boolean;
  readonly onCreated: (runId: string) => void;
}

export function NewSimulationPage({ api, canCreate, onCreated }: NewSimulationPageProps) {
  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [selected, setSelected] = useState("");
  const [count, setCount] = useState(1);
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    let active = true;
    void api.scenarios()
      .then((result) => {
        if (active) {
          setScenarios(result.items);
          setSelected((current) => current || result.items[0]?.scenario_id || "");
        }
      })
      .catch((reason: unknown) => { if (active) setError(reason); });
    return () => { active = false; };
  }, [api]);

  const create = async (): Promise<void> => {
    if (!selected || !canCreate) return;
    setCreating(true);
    setError(null);
    try {
      const scenarioIds = count === 1
        ? [selected]
        : (scenarios ?? []).map((scenario) => scenario.scenario_id);
      const result = await api.createBatch(scenarioIds, count, crypto.randomUUID());
      const first = result.items[0];
      if (first) onCreated(first.run_id);
    } catch (reason: unknown) {
      setError(reason);
    } finally {
      setCreating(false);
    }
  };

  return <>
    <section className="page-hero compact">
      <div>
        <span className="eyebrow">CONTROLLED SCENARIO CATALOG</span>
        <h2>New defensive simulation batch</h2>
        <p>Queue up to ten independent Shadow simulations. Every countermeasure receives an automated pre-check and remains blocked on individual human approval.</p>
      </div>
    </section>
    <Panel title="Select a scenario" eyebrow="API ALLOW-LIST">
      {error
        ? <ErrorState error={error} />
        : scenarios === null
          ? <LoadingState />
          : scenarios.length === 0
            ? <EmptyState>The API has not configured any scenarios.</EmptyState>
            : <>
              <div className="scenario-grid">
                {scenarios.map((scenario) => <button key={scenario.scenario_id} className={selected === scenario.scenario_id ? "scenario-card selected" : "scenario-card"} onClick={() => setSelected(scenario.scenario_id)}><span className="scenario-icon">◇</span><b>{scenario.scenario_id}</b><small>Controlled simulation scenario</small></button>)}
              </div>
              <div className="batch-controls">
                <label>Simulation count
                  <input aria-label="Simulation count" type="number" min={1} max={10} value={count} onChange={(event) => setCount(Math.min(10, Math.max(1, Number(event.target.value))))} />
                </label>
                <div>
                  <button className="secondary-button" onClick={() => setCount(5)}>5 simulations</button>
                  <button className="secondary-button" onClick={() => setCount(10)}>10 simulations</button>
                </div>
              </div>
              {!canCreate ? <p className="permission-note">Your verified identity cannot create simulations.</p> : null}
              <div className="create-bar">
                <span>{count === 1 ? "One selected scenario." : "Batch rotates through the allow-listed catalog."} Each run receives its own review and HITL decision.</span>
                <button className="primary-button" disabled={!canCreate || !selected || creating} onClick={() => void create()}>{creating ? "Creating…" : `Create ${count} simulation${count === 1 ? "" : "s"}`}</button>
              </div>
            </>}
    </Panel>
  </>;
}

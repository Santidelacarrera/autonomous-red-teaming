"""Run the bounded Shadow attack simulation and render a remediation candidate."""

from __future__ import annotations

import asyncio
from typing import cast

from seed_db import SOURCE_ASSET_ID, load_neo4j_settings

from art_sim.agents.graph import AttackSimulationGraph
from art_sim.agents.models import ShadowEnvironmentScope
from art_sim.agents.planner import MitrePathPlanner
from art_sim.agents.recon import ReconAgent
from art_sim.agents.state import AgentState
from art_sim.agents.supervisor import SupervisorAgent
from art_sim.infrastructure.cypher_validator import CypherValidator
from art_sim.infrastructure.neo4j_graph_repository import Neo4jGraphRepository
from art_sim.remediation.agent import RemediationAgent
from art_sim.remediation.generator import PolicyRemediationGenerator
from art_sim.remediation.models import RemediationRequest
from art_sim.security.sanitizer import PromptInjectionSanitizer


async def main() -> None:
    """Execute only simulated Shadow actions; GitHub publication is intentionally excluded."""
    repository = Neo4jGraphRepository(load_neo4j_settings(), CypherValidator())
    async with repository:
        path = await repository.find_shortest_path_to_crown_jewel(SOURCE_ASSET_ID)
        scope = ShadowEnvironmentScope(allowed_asset_ids=frozenset(path.asset_ids))
        graph = AttackSimulationGraph(
            ReconAgent(repository, PromptInjectionSanitizer()),
            MitrePathPlanner(),
            SupervisorAgent(),
        ).compile()
        initial_state: AgentState = {
            "source_asset_id": SOURCE_ASSET_ID,
            "shadow_scope": scope,
            "command_history": [],
            "supervisor_findings": [],
        }
        final_state = cast(AgentState, await graph.ainvoke(initial_state))

    plan = final_state["attack_plan"]
    simulation = final_state["simulation_result"]
    planner_context = final_state["planner_context"]
    target = next(asset for asset in planner_context.assets if asset.asset_id == plan.target_asset_id)
    artifact = await RemediationAgent(PolicyRemediationGenerator()).generate(
        RemediationRequest(plan=plan, simulation=simulation, target=target)
    )

    print("Shadow simulation completed.")
    print(f"Plan status: {final_state['plan_status'].value}")
    print(f"Simulation status: {simulation.status.value}")
    print(f"Remediation artifact: {artifact.file_path}")
    print(artifact.content)


if __name__ == "__main__":
    asyncio.run(main())

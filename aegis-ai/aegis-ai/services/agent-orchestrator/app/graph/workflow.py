"""
Aegis AI — Agent Orchestrator LangGraph State Machine

Nodes (in order):
  triage_node   → calls Ollama, falls back to heuristics on any error
  playbook_node → selects playbook, instantiates ActionSteps
  approval_node → routes: automated → execute_node | supervised/manual → END
  execute_node  → runs steps sequentially, collects results
  report_node   → builds final report

The graph compiles and runs WITHOUT a live Ollama, Kafka, or PostgreSQL.
All external I/O is injected via the state dict so unit tests can mock it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict

from langgraph.graph import END, StateGraph

from app.agents.executor import ActionExecutor
from app.agents.playbooks import ActionStep, PlaybookEngine
from app.agents.triage import IncidentTriageAgent

logger = logging.getLogger(__name__)


# ── State ────────────────────────────────────────────────────────────────────

class OrchestratorState(TypedDict, total=False):
    incident: dict[str, Any]
    triage: dict[str, Any]
    selected_playbook: str
    playbook_steps: list[dict[str, Any]]
    task_id: str
    actions_results: list[dict[str, Any]]
    final_report: dict[str, Any]
    error: Optional[str]


# ── Node implementations ─────────────────────────────────────────────────────

async def triage_node(state: OrchestratorState) -> OrchestratorState:
    """Call IncidentTriageAgent — always succeeds (heuristic fallback on any error)."""
    incident = state.get("incident") or {}
    try:
        agent = IncidentTriageAgent()
        result = await agent.triage(incident)
        triage = result.model_dump()
    except Exception as exc:
        # Belt-and-suspenders: triage() already never raises, but guard anyway
        logger.error("Unexpected error in triage_node: %s", exc)
        triage = {
            "urgency_score": 0.55,
            "attack_stage": "execution",
            "recommended_response_tier": "supervised",
            "summary": f"Triage failed unexpectedly: {exc}",
            "key_indicators": ["triage_node_fallback"],
        }

    return {**state, "triage": triage}


async def playbook_node(state: OrchestratorState) -> OrchestratorState:
    """Select playbook and instantiate steps."""
    incident = state.get("incident") or {}
    triage = state.get("triage") or {}

    engine = PlaybookEngine()
    mitre_techniques: list[str] = incident.get("mitre_techniques") or []
    attack_stage: str = triage.get("attack_stage", "execution")
    severity: str = incident.get("severity", "medium")

    try:
        playbook = engine.select_playbook(mitre_techniques, attack_stage, severity)
        steps = engine.instantiate_steps(playbook, incident)

        return {
            **state,
            "selected_playbook": playbook.name,
            "playbook_steps": [s.to_dict() for s in steps],
        }
    except Exception as exc:
        logger.error("playbook_node error: %s", exc)
        return {
            **state,
            "selected_playbook": "generic_investigation",
            "playbook_steps": [
                ActionStep("collect_logs").to_dict(),
                ActionStep("escalate_to_analyst").to_dict(),
            ],
            "error": str(exc),
        }


async def approval_node(state: OrchestratorState) -> OrchestratorState:
    """
    Routing node — does NOT execute anything.
    Automated incidents pass through; supervised/manual stop here (pending approval).
    The actual routing decision is in _route_after_approval().
    """
    return state  # state is passed unchanged; routing logic is in the conditional edge


def _route_after_approval(state: OrchestratorState) -> str:
    """Edge function: route based on recommended_response_tier."""
    triage = state.get("triage") or {}
    tier = triage.get("recommended_response_tier", "supervised")
    if tier == "automated":
        return "execute_node"
    return END  # supervised / manual → pending human approval


async def execute_node(state: OrchestratorState) -> OrchestratorState:
    """Run playbook steps sequentially and collect results."""
    incident = state.get("incident") or {}
    raw_steps = state.get("playbook_steps") or []

    executor = ActionExecutor()
    results: list[dict[str, Any]] = []

    for step_dict in raw_steps:
        step = ActionStep(
            action_type=step_dict.get("action_type", "unknown"),
            target=step_dict.get("target", ""),
            parameters=step_dict.get("parameters", {}),
        )
        result = await executor.execute(step, incident)
        results.append(result)
        logger.info(
            "Action %s → %s (%dms)",
            result["action_type"],
            result["status"],
            result["duration_ms"],
        )

    return {**state, "actions_results": results}


async def report_node(state: OrchestratorState) -> OrchestratorState:
    """Build final report and attach to state."""
    incident = state.get("incident") or {}
    triage = state.get("triage") or {}
    results = state.get("actions_results") or []

    success_count = sum(1 for r in results if r.get("status") == "success")
    failed_count = sum(1 for r in results if r.get("status") == "failed")

    final_report = {
        "incident_id": incident.get("id") or incident.get("incident_id"),
        "incident_title": incident.get("title") or incident.get("incident_title"),
        "severity": incident.get("severity"),
        "triage_summary": triage.get("summary"),
        "urgency_score": triage.get("urgency_score"),
        "attack_stage": triage.get("attack_stage"),
        "playbook": state.get("selected_playbook"),
        "total_actions": len(results),
        "successful_actions": success_count,
        "failed_actions": failed_count,
        "actions": results,
        "completed_at": datetime.now(tz=timezone.utc).isoformat(),
        "error": state.get("error"),
    }

    return {**state, "final_report": final_report}


# ── Build the graph ──────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(OrchestratorState)

    graph.add_node("triage_node", triage_node)
    graph.add_node("playbook_node", playbook_node)
    graph.add_node("approval_node", approval_node)
    graph.add_node("execute_node", execute_node)
    graph.add_node("report_node", report_node)

    graph.set_entry_point("triage_node")

    graph.add_edge("triage_node", "playbook_node")
    graph.add_edge("playbook_node", "approval_node")
    graph.add_conditional_edges(
        "approval_node",
        _route_after_approval,
        {"execute_node": "execute_node", END: END},
    )
    graph.add_edge("execute_node", "report_node")
    graph.add_edge("report_node", END)

    return graph


# Compile once at module level — this must succeed without any live services
compiled_graph = build_graph().compile()


async def run_pipeline(incident: dict[str, Any], task_id: str = "") -> OrchestratorState:
    """
    Entry point for the full agent pipeline.
    Returns the final state regardless of LLM / Kafka availability.
    """
    initial_state: OrchestratorState = {
        "incident": incident,
        "triage": {},
        "selected_playbook": "",
        "playbook_steps": [],
        "task_id": task_id,
        "actions_results": [],
        "final_report": {},
        "error": None,
    }

    final_state = await compiled_graph.ainvoke(initial_state)
    return final_state

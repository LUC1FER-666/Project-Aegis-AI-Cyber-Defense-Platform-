"""
Defense Agent — LangGraph ReAct-style agent
Tools: analyze_threat_patterns, generate_narrative, execute_preemptive_action,
       send_notification, assess_asset_risk

Compiles and runs without a live Ollama, DB, or Kafka instance.
All external I/O is performed via async functions that handle their own errors.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict

from langgraph.graph import END, StateGraph

from app.agents.narrator import AttackNarrativeEngine
from app.agents.notifier import SOCNotificationSystem, broadcast
from app.agents.preemptive import PreemptiveActionEngine
from app.agents.predictor import PredictiveThreatMonitor
from app.config import get_settings

logger = logging.getLogger(__name__)


# ── State ─────────────────────────────────────────────────────────────────────

class DefenseAgentState(TypedDict, total=False):
    # Input context
    events: list[dict[str, Any]]
    incidents: list[dict[str, Any]]
    # Working memory
    current_threats: list[str]
    predictions: list[dict[str, Any]]
    narratives: list[dict[str, Any]]
    actions_taken: list[dict[str, Any]]
    notifications_sent: list[dict[str, Any]]
    # Control
    error: Optional[str]
    completed_at: Optional[str]


# ── Tool implementations ──────────────────────────────────────────────────────

async def analyze_threat_patterns(state: DefenseAgentState) -> DefenseAgentState:
    """Run PredictiveThreatMonitor against events in state."""
    events = state.get("events") or []
    incidents = state.get("incidents") or []

    monitor = PredictiveThreatMonitor()
    predictions = monitor.analyze(events)

    # Also convert confirmed incidents to threat descriptors
    threats = [inc.get("title") or inc.get("incident_id") or "unknown" for inc in incidents]
    for pred in predictions:
        threats.append(f"{pred['threat_type']} (confidence={pred['confidence']:.0%})")

    logger.info("analyze_threat_patterns: %d predictions, %d incident threats", len(predictions), len(incidents))
    return {**state, "predictions": predictions, "current_threats": threats}


async def generate_narrative(state: DefenseAgentState) -> DefenseAgentState:
    """Generate narratives for high-confidence predictions and confirmed incidents."""
    settings = get_settings()
    narrator = AttackNarrativeEngine()
    narratives: list[dict[str, Any]] = list(state.get("narratives") or [])

    # Narratives for high-confidence predictions
    for pred in (state.get("predictions") or []):
        if float(pred.get("confidence") or 0) > 0.80:
            try:
                narrative = await narrator.generate(pred)
                narrative["source_type"] = "prediction"
                narrative["source_id"] = pred.get("prediction_id", "unknown")
                narratives.append(narrative)
            except Exception as exc:
                logger.warning("Narrative generation failed for prediction: %s", exc)

    # Narratives for confirmed incidents
    for inc in (state.get("incidents") or []):
        try:
            narrative = await narrator.generate(inc)
            narrative["source_type"] = "incident"
            narrative["source_id"] = inc.get("incident_id") or inc.get("id") or "unknown"
            narratives.append(narrative)
        except Exception as exc:
            logger.warning("Narrative generation failed for incident: %s", exc)

    logger.info("generate_narrative: %d narratives generated", len(narratives))
    return {**state, "narratives": narratives}


async def execute_preemptive_action(state: DefenseAgentState) -> DefenseAgentState:
    """Execute preemptive actions for predictions above threshold."""
    settings = get_settings()
    threshold = settings.prediction_confidence_threshold
    engine = PreemptiveActionEngine()
    actions_taken: list[dict[str, Any]] = list(state.get("actions_taken") or [])

    for pred in (state.get("predictions") or []):
        if float(pred.get("confidence") or 0) >= threshold:
            try:
                results = await engine.execute_for_prediction(pred)
                actions_taken.extend(results)
            except Exception as exc:
                logger.error("Preemptive action execution failed: %s", exc)

    logger.info("execute_preemptive_action: %d actions executed", len(actions_taken))
    return {**state, "actions_taken": actions_taken}


async def send_notification(state: DefenseAgentState) -> DefenseAgentState:
    """Create and broadcast SOC notifications for all predictions, actions, and narratives."""
    notifier = SOCNotificationSystem()
    notifications_sent: list[dict[str, Any]] = list(state.get("notifications_sent") or [])

    # Prediction alerts
    for pred in (state.get("predictions") or []):
        try:
            notif = notifier.prediction_alert(pred)
            notifications_sent.append(notif)
            await broadcast(notif)
        except Exception as exc:
            logger.warning("Failed to broadcast prediction notification: %s", exc)

    # Confirmed incident notifications
    for inc in (state.get("incidents") or []):
        try:
            notif = notifier.attack_confirmed(inc)
            notifications_sent.append(notif)
            await broadcast(notif)
        except Exception as exc:
            logger.warning("Failed to broadcast incident notification: %s", exc)

    # Preemptive action notifications
    predictions_by_id = {p["prediction_id"]: p for p in (state.get("predictions") or []) if "prediction_id" in p}
    for action in (state.get("actions_taken") or []):
        try:
            pred = predictions_by_id.get(action.get("prediction_id", ""), {})
            notif = notifier.preemptive_action_taken(action, pred)
            notifications_sent.append(notif)
            await broadcast(notif)
        except Exception as exc:
            logger.warning("Failed to broadcast action notification: %s", exc)

    # Briefing ready notifications
    for narrative in (state.get("narratives") or []):
        try:
            notif = notifier.briefing_ready(narrative, narrative.get("source_id", "unknown"))
            notifications_sent.append(notif)
            await broadcast(notif)
        except Exception as exc:
            logger.warning("Failed to broadcast briefing notification: %s", exc)

    logger.info("send_notification: %d notifications sent", len(notifications_sent))
    return {**state, "notifications_sent": notifications_sent}


async def assess_asset_risk(state: DefenseAgentState) -> DefenseAgentState:
    """
    Calculate risk scores for assets mentioned in predictions/incidents.
    Kept lightweight — no external calls, purely derived from current state.
    """
    risk_scores: dict[str, float] = {}

    for pred in (state.get("predictions") or []):
        for asset in (pred.get("affected_assets") or []):
            existing = risk_scores.get(str(asset), 0.0)
            risk_scores[str(asset)] = min(1.0, existing + float(pred.get("confidence") or 0) * 0.3)

    for inc in (state.get("incidents") or []):
        for asset in (inc.get("affected_assets") or inc.get("asset_ids") or []):
            existing = risk_scores.get(str(asset), 0.0)
            sev_map = {"critical": 0.4, "high": 0.3, "medium": 0.2, "low": 0.1}
            risk_scores[str(asset)] = min(1.0, existing + sev_map.get(str(inc.get("severity") or "medium").lower(), 0.2))

    logger.info("assess_asset_risk: risk calculated for %d assets", len(risk_scores))
    extra = state.get("error")  # preserve error key
    return {**state, "error": extra}


async def finalize(state: DefenseAgentState) -> DefenseAgentState:
    return {**state, "completed_at": datetime.now(tz=timezone.utc).isoformat()}


# ── Build graph ───────────────────────────────────────────────────────────────

def build_defense_graph() -> StateGraph:
    graph = StateGraph(DefenseAgentState)

    graph.add_node("analyze_threat_patterns", analyze_threat_patterns)
    graph.add_node("assess_asset_risk", assess_asset_risk)
    graph.add_node("execute_preemptive_action", execute_preemptive_action)
    graph.add_node("generate_narrative", generate_narrative)
    graph.add_node("send_notification", send_notification)
    graph.add_node("finalize", finalize)

    graph.set_entry_point("analyze_threat_patterns")
    graph.add_edge("analyze_threat_patterns", "assess_asset_risk")
    graph.add_edge("assess_asset_risk", "execute_preemptive_action")
    graph.add_edge("execute_preemptive_action", "generate_narrative")
    graph.add_edge("generate_narrative", "send_notification")
    graph.add_edge("send_notification", "finalize")
    graph.add_edge("finalize", END)

    return graph


# Compile at module level — must succeed without any live services
compiled_defense_graph = build_defense_graph().compile()


async def run_defense_agent(
    events: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
) -> DefenseAgentState:
    """Entry point — run the full defense agent pipeline."""
    initial: DefenseAgentState = {
        "events": events or [],
        "incidents": incidents or [],
        "current_threats": [],
        "predictions": [],
        "narratives": [],
        "actions_taken": [],
        "notifications_sent": [],
        "error": None,
        "completed_at": None,
    }
    return await compiled_defense_graph.ainvoke(initial)

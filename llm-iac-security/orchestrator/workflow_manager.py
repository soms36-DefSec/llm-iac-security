from __future__ import annotations
from typing import Any
from agents.base_agent import BaseAgent
from config.logging_config import get_logger

logger = get_logger(__name__)

class WorkflowManager:
    """Executes a linear agent sequence, threading context between agents."""
    def __init__(self, agents: list[BaseAgent]):
        if not agents: raise ValueError("At least one agent required.")
        self._agents = agents

    def execute(self, initial_context: dict[str, Any]) -> dict[str, Any]:
        context = dict(initial_context)
        for agent in self._agents:
            logger.info("agent_starting", agent=repr(agent))
            context = agent.run(context)
            logger.info("agent_finished", agent=repr(agent))
        return context

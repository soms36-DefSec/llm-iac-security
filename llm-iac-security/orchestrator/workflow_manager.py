from __future__ import annotations
import traceback
import time
from typing import Any
from agents.base_agent import BaseAgent
from config.logging_config import get_logger
from utils.exceptions import IaCSecurityError

logger = get_logger(__name__)

class WorkflowManager:
    """Executes a linear agent sequence, threading context between agents."""
    def __init__(self, agents: list[BaseAgent]):
        if not agents: raise ValueError("At least one agent required.")
        self._agents = agents

    def execute(self, initial_context: dict[str, Any]) -> dict[str, Any]:
        context = dict(initial_context)
        total_agents = len(self._agents)
        
        for i, agent in enumerate(self._agents, 1):
            agent_name = agent.__class__.__name__
            # Format: [1/3] RetrievalAgent .....
            prefix = f" [{i}/{total_agents}] {agent_name:<20} ....."
            print(prefix, end="", flush=True)
            
            start_time = time.perf_counter()
            logger.info("agent_starting", agent=repr(agent))
            try:
                context = agent.run(context)
                elapsed = time.perf_counter() - start_time
                print(f" done  ({elapsed:.1f}s)")
            except Exception as e:
                print(" failed")
                logger.debug(f"Agent {agent} failed with traceback: {traceback.format_exc()}")
                raise IaCSecurityError(f"Agent {agent_name} failed: {str(e)}") from e
            logger.info("agent_finished", agent=repr(agent))
        return context

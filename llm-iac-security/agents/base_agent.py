from abc import ABC, abstractmethod
import time
from typing import Any
from config.logging_config import get_logger

class BaseAgent(ABC):
    """Abstract base: all agents implement run() on a context dict."""
    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)
        self._start_time = 0.0

    @abstractmethod
    def run(self, context: dict[str, Any]) -> dict[str, Any]: ...

    def _log_start(self, input_summary: str):
        """Spec Section 5.13: Log start of agent execution."""
        self._start_time = time.perf_counter()
        self.logger.info("agent_starting", summary=input_summary)

    def _log_end(self, output_summary: str) -> float:
        """Spec Section 5.13: Log end of agent execution and return elapsed time."""
        elapsed = time.perf_counter() - self._start_time
        self.logger.info("agent_finished", summary=output_summary, elapsed=f"{elapsed:.2f}s")
        return elapsed

    def __repr__(self):
        return f"<{self.__class__.__name__}>"

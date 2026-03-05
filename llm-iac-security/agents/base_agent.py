from abc import ABC, abstractmethod
from typing import Any
from config.logging_config import get_logger

class BaseAgent(ABC):
    """Abstract base: all agents implement run() on a context dict."""
    def __init__(self): self.logger = get_logger(self.__class__.__name__)
    @abstractmethod
    def run(self, context: dict[str, Any]) -> dict[str, Any]: ...
    def __repr__(self): return f"<{self.__class__.__name__}>"

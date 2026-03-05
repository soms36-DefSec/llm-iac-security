from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Union

class BaseParser(ABC):
    """Abstract IaC parser interface."""
    @abstractmethod
    def parse(self, path: Union[str, Path]) -> dict[str, Any]: ...
    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]: ...
    def parse_and_normalize(self, path: Union[str, Path]) -> dict[str, Any]:
        return self.normalize(self.parse(path))

from config.logging_config import get_logger
from knowledge_base.kb_manager import KnowledgeBaseManager

logger = get_logger(__name__)

class KnowledgeBaseUpdater:
    """Scheduled updater that re-seeds KB with latest best-practice documents."""
    def __init__(self): self._kb = KnowledgeBaseManager()
    def update(self) -> int:
        logger.info("kb_update_started")
        count = self._kb.load_all_sources()
        logger.info("kb_update_completed", count=count)
        return count

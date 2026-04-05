#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.logging_config import configure_logging, get_logger
from knowledge_base.kb_manager import KnowledgeBaseManager

configure_logging()
logger = get_logger(__name__)

if __name__ == "__main__":
    logger.info("initializing_knowledge_base")
    KnowledgeBaseManager().initialize()
    logger.info("knowledge_base_ready")

#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.logging_config import configure_logging
from knowledge_base.updater import KnowledgeBaseUpdater

configure_logging()
if __name__ == "__main__":
    KnowledgeBaseUpdater().update()

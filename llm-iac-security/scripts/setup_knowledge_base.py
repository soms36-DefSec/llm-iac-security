#!/usr/bin/env python3
"""
Setup Knowledge Base — One-time script to build the vector store.

What this script does:
    1. Reads all Markdown/PDF/TXT files from  knowledge_base/sources/
    2. Splits each document into overlapping text chunks
    3. Generates embeddings for each chunk using sentence-transformers
    4. Stores everything in ChromaDB (persisted to disk)

After running this script, the knowledge base is ready for retrieval
queries via KnowledgeBaseManager.retrieve().

Usage:
    cd llm-iac-security
    python scripts/setup_knowledge_base.py
"""

import sys
from pathlib import Path

# Ensure the project root is on the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.logging_config import configure_logging, get_logger
from knowledge_base.kb_manager import KnowledgeBaseManager

configure_logging()
logger = get_logger(__name__)


def main():
    logger.info("=" * 60)
    logger.info("Knowledge Base Setup — Starting")
    logger.info("=" * 60)

    # Step 1 — Create the manager (loads embedding model + initializes ChromaDB)
    logger.info("step_1", description="Loading embedding model and initializing ChromaDB...")
    kb = KnowledgeBaseManager()

    # Step 2 — Clear any existing data to avoid duplicates on re-run
    logger.info("step_2", description="Clearing existing data...")
    kb.clear()

    # Step 3 — Load all source documents
    logger.info("step_3", description="Loading and embedding source documents...")
    kb.load_all_sources()

    # Step 4 — Verify
    test_query = "S3 bucket encryption best practices"
    logger.info("step_4", description=f"Testing retrieval with query: '{test_query}'")
    results = kb.retrieve(test_query, top_k=3)

    logger.info("=" * 60)
    logger.info("Knowledge Base Setup — Complete")
    logger.info("verification_results", snippets_found=len(results))

    if results:
        for i, snippet in enumerate(results, 1):
            preview = snippet[:150].replace("\n", " ")
            logger.info(f"snippet_{i}", preview=preview)
    else:
        logger.warning("no_results", msg="No results returned — check your source documents.")

    logger.info("=" * 60)


if __name__ == "__main__":
    main()

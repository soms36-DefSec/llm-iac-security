#!/usr/bin/env python3
"""
Test RAG Pipeline — End-to-end demo of the full RAG workflow.

This script demonstrates the complete pipeline:
    1. Query the knowledge base for relevant security best practices.
    2. Build a prompt combining the retrieved context with the user's question.
    3. Send the prompt to Ollama (Llama3) for generation.
    4. Display the response.

Prerequisites:
    1. Run setup_knowledge_base.py first to populate ChromaDB.
    2. Install and start Ollama:  ollama serve
    3. Pull the model:            ollama pull llama3

Usage:
    cd llm-iac-security
    python scripts/test_rag.py
    python scripts/test_rag.py "How should I secure my IAM roles?"
"""

import sys
from pathlib import Path

# Ensure the project root is on the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.logging_config import configure_logging, get_logger
from knowledge_base.kb_manager import KnowledgeBaseManager
from llm.prompt_builder import PromptBuilder
from llm.ollama_client import OllamaClient

configure_logging()
logger = get_logger(__name__)

# Default demo query
DEFAULT_QUERY = "What are best practices to secure AWS S3 buckets?"


def run_rag_pipeline(query: str) -> str:
    """
    Execute the full RAG pipeline:
        Query → Retrieve → Build Prompt → Generate Response

    Args:
        query: The user's security question.

    Returns:
        The LLM's generated response text.
    """
    print("\n" + "=" * 70)
    print("  RAG Pipeline Demo")
    print("=" * 70)

    # --- Step 1: Retrieve relevant context from the knowledge base ---
    print(f"\n[Step 1] Retrieving context for: \"{query}\"")
    kb = KnowledgeBaseManager()
    snippets = kb.retrieve(query, top_k=5)

    print(f"         Found {len(snippets)} relevant snippets:")
    for i, snippet in enumerate(snippets, 1):
        preview = snippet[:100].replace("\n", " ").strip()
        print(f"         [{i}] {preview}...")

    # --- Step 2: Build the prompt ---
    print(f"\n[Step 2] Building prompt with retrieved context...")
    prompt = PromptBuilder.build_rag_query(query, snippets)
    print(f"         Prompt length: {len(prompt)} characters")

    # --- Step 3: Send to Ollama (Llama3) ---
    print(f"\n[Step 3] Sending prompt to Ollama (llama3)...")
    client = OllamaClient()

    if not client.is_available():
        print("\n  ERROR: Ollama is not running or llama3 is not pulled.")
        print("  Fix with:")
        print("    1. Start Ollama:  ollama serve")
        print("    2. Pull model:    ollama pull llama3")
        print("\n  Showing the prompt that WOULD be sent:\n")
        print("-" * 50)
        print(prompt)
        print("-" * 50)
        return ""

    system_prompt = (
        "You are an AWS cloud security expert.  "
        "Use the provided context to give specific, actionable security recommendations.  "
        "Reference AWS best practices and security benchmarks where applicable."
    )

    response = client.generate(prompt, system=system_prompt)

    # --- Step 4: Display the response ---
    print(f"\n[Step 4] LLM Response:")
    print("-" * 50)
    print(response)
    print("-" * 50)

    return response


def main():
    # Use a custom query from command-line args, or the default
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
    else:
        query = DEFAULT_QUERY

    response = run_rag_pipeline(query)

    if response:
        print(f"\n  Pipeline completed successfully!")
        print(f"  Response length: {len(response)} characters")
    print()


if __name__ == "__main__":
    main()

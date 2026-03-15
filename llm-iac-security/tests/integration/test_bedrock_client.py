"""Integration tests for LLM clients — requires live services."""
import pytest


@pytest.mark.skip(reason="Requires live Amazon Bedrock access")
def test_bedrock_invoke():
    from llm.bedrock_client import BedrockClient
    client = BedrockClient()
    resp = client.invoke(messages=[{"role": "user", "content": "Say hello."}])
    assert isinstance(resp, str) and len(resp) > 0


@pytest.mark.skip(reason="Requires Ollama running locally")
def test_ollama_invoke():
    from llm.bedrock_client import OllamaClient
    client = OllamaClient()
    resp = client.invoke(messages=[{"role": "user", "content": "Say hello."}])
    assert isinstance(resp, str) and len(resp) > 0

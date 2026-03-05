"""Integration test stub for Bedrock client (requires live AWS)."""
import pytest

@pytest.mark.skip(reason="Requires live Amazon Bedrock access")
def test_bedrock_invoke():
    from llm.bedrock_client import BedrockClient
    client = BedrockClient()
    resp = client.invoke(messages=[{"role": "user", "content": "Say hello."}])
    assert isinstance(resp, str) and len(resp) > 0

from __future__ import annotations
import json
from config.bedrock_config import bedrock_config
from config.logging_config import get_logger
from utils.aws_utils import get_client
from utils.exceptions import EmbeddingError

logger = get_logger(__name__)

class TitanEmbeddings:
    """Generates text embeddings via Amazon Titan Text Embeddings V2."""
    def __init__(self): self._client = get_client("bedrock-runtime")

    def embed(self, text: str) -> list[float]:
        body = json.dumps({"inputText": text, "dimensions": 512, "normalize": True})
        try:
            resp = self._client.invoke_model(
                modelId=bedrock_config.embedding_model_id,
                contentType="application/json", accept="application/json", body=body)
            return json.loads(resp["body"].read())["embedding"]
        except Exception as e: raise EmbeddingError(str(e)) from e

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]

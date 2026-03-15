"""Embedding providers: Titan (AWS) and HuggingFace sentence-transformers (local)."""
from __future__ import annotations
import json
from abc import ABC, abstractmethod
from config.settings import settings
from config.logging_config import get_logger
from utils.exceptions import EmbeddingError

logger = get_logger(__name__)


class BaseEmbeddings(ABC):
    """Abstract interface for text embedding providers."""
    @abstractmethod
    def embed(self, text: str) -> list[float]: ...

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


class TitanEmbeddings(BaseEmbeddings):
    """Generates text embeddings via Amazon Titan Text Embeddings V2."""
    def __init__(self):
        from config.bedrock_config import bedrock_config
        from utils.aws_utils import get_client
        self._client = get_client("bedrock-runtime")
        self._model_id = bedrock_config.embedding_model_id

    def embed(self, text: str) -> list[float]:
        body = json.dumps({"inputText": text, "dimensions": 1024, "normalize": True})
        try:
            resp = self._client.invoke_model(
                modelId=self._model_id,
                contentType="application/json", accept="application/json", body=body)
            return json.loads(resp["body"].read())["embedding"]
        except Exception as e:
            raise EmbeddingError(f"Titan embedding failed: {e}") from e


class HuggingFaceEmbeddings(BaseEmbeddings):
    """Generates text embeddings using HuggingFace sentence-transformers (local, free)."""
    def __init__(self):
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(settings.local_embedding.model_name)
            logger.info("huggingface_embeddings_loaded", model=settings.local_embedding.model_name)
        except ImportError:
            raise EmbeddingError(
                "sentence-transformers is required for local mode. "
                "Install it with: pip install sentence-transformers"
            )
        except Exception as e:
            raise EmbeddingError(f"Failed to load HuggingFace model: {e}") from e

    def embed(self, text: str) -> list[float]:
        try:
            embedding = self._model.encode(text, normalize_embeddings=True)
            return embedding.tolist()
        except Exception as e:
            raise EmbeddingError(f"HuggingFace embedding failed: {e}") from e

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        try:
            embeddings = self._model.encode(texts, normalize_embeddings=True)
            return embeddings.tolist()
        except Exception as e:
            raise EmbeddingError(f"HuggingFace batch embedding failed: {e}") from e


def get_embeddings() -> BaseEmbeddings:
    """Factory: returns the correct embedding provider based on MODE setting."""
    if settings.is_local:
        return HuggingFaceEmbeddings()
    return TitanEmbeddings()

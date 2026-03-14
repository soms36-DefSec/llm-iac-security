"""
Embeddings Module — Converts text into numerical vectors (embeddings).

What are embeddings?
    Embeddings are lists of numbers that represent the *meaning* of a piece of text.
    Texts with similar meanings will have similar embeddings, which lets us find
    relevant documents by comparing their embeddings to a query's embedding.

This module supports two backends:
    - LOCAL mode:  Uses HuggingFace's "all-MiniLM-L6-v2" model from the
                   sentence-transformers library. Runs entirely on your machine
                   — no internet or API keys required.  Produces 384-dimensional
                   embeddings.
    - AWS mode:    Uses Amazon Titan Text Embeddings V2 via AWS Bedrock.
                   Requires valid AWS credentials and Bedrock access.
                   Produces 1024-dimensional embeddings.

The mode is determined by APP_MODE in your .env file (default: "local").
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import List

from config.logging_config import get_logger
from config.settings import settings
from utils.exceptions import EmbeddingError

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Abstract base — defines the interface every embedding backend must follow
# ---------------------------------------------------------------------------
class BaseEmbeddings(ABC):
    """
    Base class for all embedding providers.

    Every subclass must implement:
        embed(text)       → list of floats  (single text)
        embed_batch(texts) → list of list of floats  (multiple texts)
    """

    @abstractmethod
    def embed(self, text: str) -> List[float]:
        """Convert a single string into a numerical embedding vector."""
        ...

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Convert a list of strings into a list of embedding vectors."""
        ...

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Return the dimensionality of the embedding vectors this backend produces."""
        ...


# ---------------------------------------------------------------------------
# LOCAL backend — HuggingFace sentence-transformers (all-MiniLM-L6-v2)
# ---------------------------------------------------------------------------
class LocalEmbeddings(BaseEmbeddings):
    """
    Generates embeddings locally using the all-MiniLM-L6-v2 model.

    This is a small, fast model that runs on CPU.  It produces 384-dimensional
    vectors and is great for development and testing without AWS credentials.
    """

    # The model name from HuggingFace Hub
    MODEL_NAME = "all-MiniLM-L6-v2"
    _DIMENSION = 384

    def __init__(self):
        try:
            from sentence_transformers import SentenceTransformer

            logger.info("loading_local_embedding_model", model=self.MODEL_NAME)
            self._model = SentenceTransformer(self.MODEL_NAME)
        except ImportError as e:
            raise EmbeddingError(
                "sentence-transformers is required for local mode. "
                "Install it with: pip install sentence-transformers"
            ) from e
        except Exception as e:
            raise EmbeddingError(f"Failed to load local embedding model: {e}") from e

    @property
    def dimension(self) -> int:
        return self._DIMENSION

    def embed(self, text: str) -> List[float]:
        """Embed a single text string using the local model."""
        try:
            # encode() returns a numpy array; we convert to a plain Python list
            vector = self._model.encode(text, normalize_embeddings=True)
            return vector.tolist()
        except Exception as e:
            raise EmbeddingError(f"Local embedding failed: {e}") from e

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple texts in one call (more efficient than calling embed() in a loop)."""
        try:
            vectors = self._model.encode(texts, normalize_embeddings=True)
            return [v.tolist() for v in vectors]
        except Exception as e:
            raise EmbeddingError(f"Local batch embedding failed: {e}") from e


# ---------------------------------------------------------------------------
# AWS backend — Amazon Titan Text Embeddings V2 via Bedrock
# ---------------------------------------------------------------------------
class TitanEmbeddings(BaseEmbeddings):
    """
    Generates embeddings using Amazon Titan Text Embeddings V2 through AWS Bedrock.

    Requires:
        - Valid AWS credentials (access key + secret, or an AWS profile)
        - Access to the Bedrock service in your configured region
    Produces 1024-dimensional normalized embedding vectors.
    """

    _DIMENSION = 1024

    def __init__(self):
        from config.bedrock_config import bedrock_config
        from utils.aws_utils import get_client

        self._model_id = bedrock_config.embedding_model_id
        self._client = get_client("bedrock-runtime")

    @property
    def dimension(self) -> int:
        return self._DIMENSION

    def embed(self, text: str) -> List[float]:
        """Send a single text to the Titan embedding API and return the vector."""
        body = json.dumps({"inputText": text, "dimensions": self._DIMENSION, "normalize": True})
        try:
            resp = self._client.invoke_model(
                modelId=self._model_id,
                contentType="application/json",
                accept="application/json",
                body=body,
            )
            return json.loads(resp["body"].read())["embedding"]
        except Exception as e:
            raise EmbeddingError(str(e)) from e

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple texts by calling the API once per text (Titan does not support native batching)."""
        return [self.embed(t) for t in texts]


# ---------------------------------------------------------------------------
# Factory function — returns the right backend based on APP_MODE
# ---------------------------------------------------------------------------
def get_embeddings() -> BaseEmbeddings:
    """
    Create and return the embedding backend matching the current APP_MODE setting.

    Returns LocalEmbeddings when mode is "local", TitanEmbeddings when mode is "aws".
    """
    mode = settings.app.mode.lower()
    if mode == "local":
        logger.info("using_local_embeddings")
        return LocalEmbeddings()
    elif mode == "aws":
        logger.info("using_aws_titan_embeddings")
        return TitanEmbeddings()
    else:
        raise EmbeddingError(f"Unknown APP_MODE '{mode}'. Use 'local' or 'aws'.")

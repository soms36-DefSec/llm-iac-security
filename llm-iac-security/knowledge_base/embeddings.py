"""
Dual-mode embedding wrapper for LLM IaC Security Scanner.

Local mode: uses HuggingFace sentence-transformers (all-MiniLM-L6-v2).
AWS mode:   uses Amazon Titan Text Embeddings V2 via Bedrock.

The mode is selected automatically from config.settings.MODE; no caller
needs to know which backend is active.
"""
from __future__ import annotations
import json
import logging
from typing import Optional

import config.settings as settings
from utils.exceptions import KnowledgeBaseError

logger = logging.getLogger(__name__)


class EmbeddingModel:
    """Dual-mode text embedding wrapper.

    Provides a uniform interface regardless of whether the system is running
    in local mode (HuggingFace) or AWS mode (Amazon Titan Embeddings V2).

    Args:
        mode: Override the mode from settings. Useful for testing.

    Raises:
        KnowledgeBaseError: If the embedding backend cannot be initialised.
    """

    def __init__(self, mode: Optional[str] = None) -> None:
        """Initialise the appropriate embedding backend based on MODE.

        Args:
            mode: 'local' or 'aws'. Defaults to settings.MODE.

        Raises:
            KnowledgeBaseError: If the backend fails to initialise.
        """
        self._mode = mode or settings.MODE
        self._model = None  # lazy-initialised
        # File-backed cache keyed by SHA-256 of input text (MISS-08)
        try:
            from storage.local_cache import LocalCache
            self._cache: Optional[object] = LocalCache("embeddings")
        except Exception:
            self._cache = None

    def _get_model(self):
        """Lazy-initialise the underlying model/client.

        Returns:
            The initialised model or Bedrock client.

        Raises:
            KnowledgeBaseError: If initialisation fails.
        """
        if self._model is not None:
            return self._model

        try:
            if self._mode == "local":
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(settings.LOCAL_EMBED_MODEL)
                logger.info(
                    "Local embedding model loaded: %s", settings.LOCAL_EMBED_MODEL
                )
            else:
                import boto3
                self._model = boto3.client(
                    "bedrock-runtime", region_name=settings.AWS_REGION
                )
                logger.info(
                    "Bedrock embedding client initialised: %s",
                    settings.BEDROCK_EMBED_MODEL_ID,
                )
        except Exception as exc:
            raise KnowledgeBaseError(
                f"Failed to initialise embedding model (mode={self._mode}): {exc}"
            ) from exc

        return self._model

    def embed_text(self, text: str) -> list[float]:
        """Embed a single text string into a float vector.

        Results are cached on disk by SHA-256 of the input text to avoid
        re-embedding the same KB documents on every RetrievalAgent init.

        Args:
            text: The input string to embed.

        Returns:
            A list of floats representing the embedding vector.

        Raises:
            KnowledgeBaseError: If the embedding call fails.
        """
        # Check disk cache first (MISS-08)
        if self._cache is not None:
            try:
                cached = self._cache.get(text)
                if cached is not None:
                    return cached
            except Exception:
                pass  # Cache miss or error — proceed to embed

        try:
            model = self._get_model()
            if self._mode == "local":
                result = model.encode(text, normalize_embeddings=True).tolist()
            else:
                body = json.dumps(
                    {
                        "inputText": text,
                        "dimensions": 1024,
                        "normalize": True,
                    }
                )
                response = model.invoke_model(
                    modelId=settings.BEDROCK_EMBED_MODEL_ID,
                    contentType="application/json",
                    accept="application/json",
                    body=body,
                )
                result = json.loads(response["body"].read())["embedding"]

            # Persist to disk cache for next run (MISS-08)
            if self._cache is not None:
                try:
                    self._cache.set(text, result)
                except Exception:
                    pass  # Cache write failure is non-fatal

            return result
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"embed_text failed (mode={self._mode}): {exc}"
            ) from exc

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of texts.

        For local mode uses batch encoding for efficiency. AWS mode falls
        back to sequential calls (Titan does not expose a batch API).

        Args:
            texts: List of strings to embed.

        Returns:
            A list of embedding vectors, one per input text.

        Raises:
            KnowledgeBaseError: If any embedding call fails.
        """
        if not texts:
            return []

        try:
            if self._mode == "local":
                model = self._get_model()
                vectors = model.encode(texts, normalize_embeddings=True)
                return [v.tolist() for v in vectors]
            else:
                return [self.embed_text(t) for t in texts]
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"embed_batch failed (mode={self._mode}): {exc}"
            ) from exc

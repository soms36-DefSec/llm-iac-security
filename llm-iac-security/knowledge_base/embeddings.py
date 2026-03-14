"""
Embeddings Module — Converts text into numerical vectors (embeddings).

What are embeddings?
    Embeddings are lists of numbers that represent the *meaning* of a piece of text.
    Texts with similar meanings will have similar embeddings (close in vector space),
    which lets us find relevant documents by comparing their embeddings to a query.

This module uses HuggingFace's "all-MiniLM-L6-v2" model from the
sentence-transformers library.  It runs entirely on your machine —
no internet or API keys required after the first download (~80 MB).
It produces 384-dimensional embedding vectors.

Usage:
    from knowledge_base.embeddings import EmbeddingModel

    model = EmbeddingModel()
    vector = model.generate_embedding("S3 bucket encryption")
    vectors = model.generate_embeddings(["text1", "text2"])
"""

from __future__ import annotations

from typing import List

from config.logging_config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Model name — a small, fast model that runs well on CPU
# ---------------------------------------------------------------------------
MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384


class EmbeddingModel:
    """
    Wrapper around sentence-transformers for generating text embeddings locally.

    The model is loaded once on initialization and reused for all subsequent
    calls, which is much faster than reloading it every time.
    """

    def __init__(self, model_name: str = MODEL_NAME):
        """
        Load the embedding model into memory.

        Args:
            model_name: HuggingFace model identifier.  Defaults to all-MiniLM-L6-v2,
                        which balances quality and speed on CPU hardware.
        """
        try:
            from sentence_transformers import SentenceTransformer

            logger.info("loading_embedding_model", model=model_name)
            self._model = SentenceTransformer(model_name)
            self._dimension = EMBEDDING_DIMENSION
            logger.info("embedding_model_loaded", model=model_name, dimension=self._dimension)
        except ImportError:
            raise RuntimeError(
                "sentence-transformers is required.  Install with:\n"
                "  pip install sentence-transformers"
            )

    # ----- public API -----

    @property
    def dimension(self) -> int:
        """Return the dimensionality of embeddings this model produces (384)."""
        return self._dimension

    def generate_embedding(self, text: str) -> List[float]:
        """
        Convert a single text string into an embedding vector.

        Args:
            text: The text to embed (e.g., a document chunk or a search query).

        Returns:
            A list of 384 floats representing the text's meaning in vector space.
        """
        # encode() returns a numpy array; tolist() converts to plain Python list
        # normalize_embeddings=True ensures cosine-similarity works correctly
        vector = self._model.encode(text, normalize_embeddings=True)
        return vector.tolist()

    def generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Convert multiple texts into embedding vectors in a single batch.

        Batching is more efficient than calling generate_embedding() in a loop
        because the model can process multiple inputs in parallel on the GPU/CPU.

        Args:
            texts: A list of text strings to embed.

        Returns:
            A list of embedding vectors (each is a list of 384 floats).
        """
        vectors = self._model.encode(texts, normalize_embeddings=True)
        return [v.tolist() for v in vectors]

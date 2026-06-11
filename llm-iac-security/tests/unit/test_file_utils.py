import pytest

from utils.file_utils import chunk_text


def test_chunk_text_rejects_non_advancing_overlap():
    with pytest.raises(ValueError, match="overlap"):
        chunk_text("abcdef", chunk_size=4, overlap=4)


def test_chunk_text_rejects_invalid_chunk_size():
    with pytest.raises(ValueError, match="chunk_size"):
        chunk_text("abcdef", chunk_size=0, overlap=0)

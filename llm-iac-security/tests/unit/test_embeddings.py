import json

from knowledge_base.embeddings import TitanEmbeddings


def test_titan_v2_request_body_includes_dimensions_and_normalize():
    titan = TitanEmbeddings.__new__(TitanEmbeddings)
    titan._model_id = "amazon.titan-embed-text-v2:0"

    payload = json.loads(titan._build_request_body("hello"))

    assert payload == {
        "inputText": "hello",
        "dimensions": 1024,
        "normalize": True,
    }


def test_titan_g1_request_body_uses_input_text_only():
    titan = TitanEmbeddings.__new__(TitanEmbeddings)
    titan._model_id = "amazon.titan-embed-g1-text-02"

    payload = json.loads(titan._build_request_body("hello"))

    assert payload == {"inputText": "hello"}

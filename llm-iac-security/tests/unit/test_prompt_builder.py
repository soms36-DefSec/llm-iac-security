from llm.prompt_builder import PromptBuilder
def test_vuln_detection():
    sys, msgs = PromptBuilder.build_vulnerability_detection("summary", ["tip"])
    assert isinstance(sys, str) and msgs[0]["role"] == "user"
def test_no_snippets():
    _, msgs = PromptBuilder.build_vulnerability_detection("summary", [])
    assert "No context retrieved" in msgs[0]["content"]
def test_report():
    _, msgs = PromptBuilder.build_report_generation('{"v":[]}', "my-stack")
    assert "my-stack" in msgs[0]["content"]

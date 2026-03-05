# API Reference

## IaCSecurityPipeline.run(template_path)
**Returns:** dict with keys:
- `findings`: `{"vulnerabilities": [...], "summary": "..."}`
- `report_markdown`: str
- `report_path`: str (local file path)
- `normalized_template`: dict
- `rag_snippets`: list[str]

## KnowledgeBaseManager.retrieve(query)
**Returns:** list[str] — top-k relevant text snippets

# Agent Descriptions

## RetrievalAgent
Extracts resource types from the normalized template, generates an embedding query,
and fetches the top-k most relevant best-practice snippets from OpenSearch.

## VulnerabilityDetectionAgent
Combines the normalized template summary with RAG-retrieved context into a
structured prompt. Invokes Claude Sonnet 3.5 V2 via Bedrock and parses the
JSON vulnerability findings from the response.

## ReportGenerationAgent
Takes the structured JSON findings and template name, then invokes the LLM again
to produce a developer-friendly Markdown security report.

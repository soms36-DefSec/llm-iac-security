# Implementation and Verification Guide

This guide explains:

- how much of `base_paper.pdf` is implemented in this repo
- how the architecture works in code
- how to run and test each module
- how to test the full project with live AWS + Pinecone
- how to test IaC templates
- where reports are stored
- how mitigation and reasoning are generated

Use this file as the practical reference for the current codebase.

## 1. Does the repo thoroughly implement the base paper?

Short answer: it implements the paper's core idea well, but not every capability from the paper is fully realized in code.

### What is implemented well

The paper's main workflow is present:

1. Parse the IaC template
2. Retrieve relevant best-practice context from a vector store
3. Ask an LLM to detect misconfigurations
4. Generate a developer-friendly markdown report

That core matches the paper's multi-agent + RAG architecture.

### What is implemented in this repo

- Multi-agent orchestration
  - `RetrievalAgent`
  - `VulnerabilityDetectionAgent`
  - `ReportGenerationAgent`
- Retrieval-augmented generation
  - Bedrock Titan embeddings
  - Pinecone vector search in AWS mode
  - ChromaDB in local mode
- LLM-based vulnerability detection
  - Bedrock runtime client
  - current working model path: `global.anthropic.claude-sonnet-4-20250514-v1:0`
- Markdown report generation
- Test fixtures and mocked integration tests
- Basic evaluation script

### What is partial or simplified compared with the paper

- No separate remediation agent
  - remediation is generated inside the vulnerability findings and final report, not by its own specialized agent
- No dynamic/runtime analysis
  - the current system is static IaC analysis only
- No continuously automated knowledge-base refresh loop
  - there is a `scripts/setup_knowledge_base.py` and updater support, but not a full always-on update service
- No closed-loop CI/CD remediation workflow
  - CI/CD config templates exist, but the repo does not automatically patch templates or create remediation pull requests
- CloudFormation is the real primary path today
  - there are Terraform-related files in the repo, but the active pipeline uses `CloudFormationParser`
- False-positive control is still limited
  - for example, the clean S3 template can still be flagged for `AES256` vs `aws:kms`

### Honest implementation verdict

This repo is a good implementation of the paper's core architecture, but not a complete production realization of every claim or extension discussed in the paper. It is best described as:

- strongly aligned with the paper's core design
- operational end-to-end
- still simplified in some areas

## 2. Current working runtime

For the live AWS path, the current effective runtime is:

- Mode: `aws`
- LLM: `global.anthropic.claude-sonnet-4-20250514-v1:0`
- Embeddings: `amazon.titan-embed-text-v2:0`
- Vector DB: Pinecone
- Pinecone index: `iac-security-kb`

These values are loaded from `.env` and `config/settings.py`.

## 3. High-level architecture

The full runtime flow is:

1. CLI receives an IaC template path
2. Template is validated and parsed
3. Template is normalized into a consistent internal format
4. Retrieval agent converts the normalized template into summary text
5. Knowledge base generates an embedding for the query
6. Pinecone returns the most relevant best-practice snippets
7. Vulnerability detection agent sends:
   - template summary
   - retrieved best-practice context
   - system prompt
   to Bedrock Sonnet 4
8. LLM returns structured JSON findings
9. Report generation agent sends the findings JSON to the LLM
10. LLM returns markdown
11. Report builder writes the markdown report to disk

## 4. Where each part lives

### Entry point

- `scripts/run_scan.py`

This is the CLI entry point. It:

- reads `--mode`
- configures logging
- builds the pipeline
- runs the full scan
- prints the final report path

### Orchestration

- `orchestrator/pipeline.py`
- `orchestrator/workflow_manager.py`

`IaCSecurityPipeline` defines the full sequence:

1. parse template
2. retrieve context
3. detect vulnerabilities
4. generate report
5. save report

`WorkflowManager` runs the agents in order and passes context between them.

### Agents

- `agents/retrieval_agent.py`
- `agents/vulnerability_detection_agent.py`
- `agents/report_generation_agent.py`

Each agent receives a `context` dictionary and returns a new `context`.

### Parser

- `parsers/cloudformation_parser.py`

This turns YAML or JSON CloudFormation into a normalized structure:

- template version
- description
- parameters
- resources
- outputs

### Resource summarization

- `parsers/resource_extractor.py`

This converts normalized resources into plain-text summary lines that are used in prompts and retrieval queries.

### Knowledge base

- `knowledge_base/kb_manager.py`
- `knowledge_base/embeddings.py`
- `knowledge_base/vector_store.py`

This layer:

- reads knowledge documents
- chunks them
- embeds them
- stores/searches them in Pinecone or Chroma

### LLM layer

- `llm/bedrock_client.py`
- `llm/prompt_builder.py`
- `llm/prompt_templates.py`
- `llm/response_parser.py`

This layer:

- builds prompts
- calls Bedrock
- parses JSON vulnerability output

### Reporting

- `reporting/report_builder.py`

This writes the markdown report to disk.

## 5. How the three agents work

### RetrievalAgent

File:

- `agents/retrieval_agent.py`

Input:

- `normalized_template`

What it does:

- builds a template summary using `ResourceExtractor`
- generates an embedding for the summary
- queries Pinecone for relevant best-practice snippets

Output:

- `rag_snippets`

Verification signal:

- log line: `retrieved_snippets`

### VulnerabilityDetectionAgent

File:

- `agents/vulnerability_detection_agent.py`

Inputs:

- `normalized_template`
- `rag_snippets`

What it does:

- builds a vulnerability-detection prompt
- sends template summary + RAG context to Bedrock Sonnet 4
- expects valid JSON back

Output:

- `findings`

Verification signal:

- log line: `detections`

### ReportGenerationAgent

File:

- `agents/report_generation_agent.py`

Input:

- `findings`

What it does:

- sends the findings JSON to the LLM
- requests a markdown report

Output:

- `report_markdown`

Verification signal:

- the report is saved and `report_saved` is logged

## 6. How mitigation and reasoning are generated

This is important.

### Where the "reasoning" comes from

The repo does not implement a separate symbolic reasoning engine.

Instead, reasoning is produced by the LLM from:

- the normalized CloudFormation summary
- the retrieved best-practice snippets from the vector store
- the system prompt in `llm/prompt_templates.py`

In other words:

- template summary provides the template facts
- RAG provides contextual security guidance
- Sonnet 4 combines both to infer misconfigurations

### Where mitigation comes from

Mitigation is also generated by the LLM.

The vulnerability JSON schema includes:

- `title`
- `description`
- `remediation`
- `reference`

Then the report-generation step converts those structured findings into markdown.

### Important limitation

Mitigation is recommendation text, not an automatic code fix.

The system currently:

- explains what is wrong
- explains why
- suggests how to fix it

It does not currently:

- rewrite the IaC template automatically
- generate a patch
- commit a remediation change

## 7. Where the report is stored

Reports are saved by:

- `reporting/report_builder.py`

The output directory comes from:

- `settings.app.report_output_dir`

Current default:

- `data/reports/generated`

Filename pattern:

- `<template_name>_<UTC timestamp>.md`

Example:

- `data/reports/generated/T1_basic_s3_20260412T045319Z.md`

## 8. How to use the project

### Prerequisites

- Python 3.10+
- a virtual environment
- AWS credentials configured
- Bedrock access
- Pinecone API key
- Pinecone index `iac-security-kb`

### Activate the environment

```powershell
.venv\Scripts\Activate.ps1
```

### Check the effective runtime config

```powershell
python -c "from config.settings import settings; print('mode=', settings.app.mode); print('llm=', settings.bedrock.model_id); print('embed=', settings.bedrock.embedding_model_id); print('index=', settings.pinecone.index)"
```

### Run a scan

```powershell
python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode aws --verbose
```

### Save report to a custom path

```powershell
python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode aws --verbose --output my_report.md
```

## 9. How to test each module

### A. Parser layer

Purpose:

- verify YAML/JSON parsing
- verify normalization
- verify invalid input handling

Command:

```powershell
python -m pytest tests/unit/test_cloudformation_parser.py -q
```

What success means:

- valid templates parse
- normalized structure is produced
- bad YAML and unsupported types fail correctly

### B. Prompt layer

Purpose:

- verify prompts are built correctly
- verify template and RAG content is inserted

Command:

```powershell
python -m pytest tests/unit/test_prompt_builder.py -q
```

What success means:

- the generated prompt format matches expectations

### C. Embedding layer

Purpose:

- verify Bedrock Titan request-body generation
- verify model-specific payload handling

Command:

```powershell
python -m pytest tests/unit/test_embeddings.py -q
```

### D. Retrieval agent

Purpose:

- verify the agent receives normalized template input
- verify it adds `rag_snippets`

Command:

```powershell
python -m pytest tests/unit/test_retrieval_agent.py -q
```

### E. Vulnerability detection agent

Purpose:

- verify Bedrock client is called with the correct prompt flow
- verify parsed JSON findings are attached to context

Command:

```powershell
python -m pytest tests/unit/test_vulnerability_agent.py -q
```

### F. Report generation agent

Purpose:

- verify markdown output generation from findings

Command:

```powershell
python -m pytest tests/unit/test_report_generation_agent.py -q
```

### G. RAG integration

Purpose:

- verify knowledge-base retrieval behavior in mocked mode

Command:

```powershell
python -m pytest tests/integration/test_rag_integration.py -q
```

### H. Full mocked pipeline

Purpose:

- verify the end-to-end control flow without calling live Bedrock/Pinecone

Command:

```powershell
python -m pytest tests/integration/test_pipeline_end_to_end.py -q
```

## 10. How to test the whole project

### Recommended verification order

1. config sanity check
2. unit tests
3. mocked integration tests
4. live scan against known vulnerable templates
5. live scan against clean template
6. inspect generated markdown reports

### Full local verification commands

```powershell
python -c "from config.settings import settings; print('mode=', settings.app.mode); print('llm=', settings.bedrock.model_id); print('embed=', settings.bedrock.embedding_model_id); print('index=', settings.pinecone.index)"
python -m pytest tests/unit/test_prompt_builder.py tests/unit/test_retrieval_agent.py tests/unit/test_vulnerability_agent.py tests/unit/test_report_generation_agent.py tests/unit/test_embeddings.py -q
python -m pytest tests/unit/test_cloudformation_parser.py -q
python -m pytest tests/integration/test_rag_integration.py -q
python -m pytest tests/integration/test_pipeline_end_to_end.py -q
```

### Live AWS verification commands

```powershell
python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode aws --verbose
python scripts/run_scan.py tests/fixtures/templates/T2_iam_roles.yaml --mode aws --verbose
python scripts/run_scan.py tests/fixtures/templates/T3_security_groups.yaml --mode aws --verbose
python scripts/run_scan.py tests/fixtures/templates/T4_rds_encrypted.yaml --mode aws --verbose
python scripts/run_scan.py tests/fixtures/templates/T10_clean_template.yaml --mode aws --verbose
```

### What to look for in the logs

You should see:

- `pipeline_started`
- `agent_starting`
- `retrieved_snippets`
- `detections`
- `report_saved`
- `pipeline_completed`

## 11. How to test IaC templates

You can test any supported CloudFormation template by passing the file path to `run_scan.py`.

### Example

```powershell
python scripts/run_scan.py path\to\my_template.yaml --mode aws --verbose
```

### Supported formats

- `.yaml`
- `.yml`
- `.json`

### Good practice for template testing

Test at least these categories:

- S3 misconfigurations
- IAM over-permissive roles
- security groups
- RDS encryption
- one clean/no-known-vulnerability template

The repo already includes fixtures under:

- `tests/fixtures/templates`

## 12. How to test the functionality of each architectural layer

### Layer 1: Validation

File:

- `utils/validation.py`

Functionality:

- checks template existence
- checks supported extension

Validation method:

- run bad path / bad extension cases

### Layer 2: Parsing and normalization

File:

- `parsers/cloudformation_parser.py`

Functionality:

- loads YAML/JSON
- produces normalized structure

Validation method:

- parser unit tests

### Layer 3: Template summarization

File:

- `parsers/resource_extractor.py`

Functionality:

- converts normalized resources into prompt-friendly text

Validation method:

- inspect `to_summary_text()` output manually in a Python one-liner if needed:

```powershell
python -c "from parsers.cloudformation_parser import CloudFormationParser; from parsers.resource_extractor import ResourceExtractor; raw=CloudFormationParser().parse('tests/fixtures/templates/T1_basic_s3.yaml'); norm=CloudFormationParser().normalize(raw); print(ResourceExtractor(norm).to_summary_text())"
```

### Layer 4: Embeddings + vector search

Files:

- `knowledge_base/embeddings.py`
- `knowledge_base/vector_store.py`
- `knowledge_base/kb_manager.py`

Functionality:

- embed the query
- search Pinecone
- return best-practice snippets

Validation method:

- check `retrieved_snippets count=...` in live logs
- run mocked integration tests

### Layer 5: LLM vulnerability analysis

Files:

- `llm/prompt_builder.py`
- `llm/prompt_templates.py`
- `llm/response_parser.py`
- `agents/vulnerability_detection_agent.py`

Functionality:

- create the security-analysis prompt
- send it to Bedrock
- parse returned JSON findings

Validation method:

- unit test for the agent
- live scan produces `detections count=...`

### Layer 6: Report generation

Files:

- `agents/report_generation_agent.py`
- `reporting/report_builder.py`

Functionality:

- transform findings JSON into readable markdown
- save report to disk

Validation method:

- unit test
- confirm report path printed after scan

## 13. How to evaluate accuracy

There is a simple evaluation script:

- `scripts/evaluate_results.py`

It computes:

- precision
- recall
- F1

Based on:

- `tests/fixtures/ground_truth/annotations.json`

Run:

```powershell
python scripts/evaluate_results.py
```

Note that this script only evaluates against the current annotation file. It is not a full benchmark harness for every live run.

## 14. Known current behavior and limitations

### False positives still happen

Example:

- `T10_clean_template.yaml` can still be flagged because the model treats `AES256` instead of `aws:kms` as a security finding

That means:

- the system is working
- the prompt/policy is still somewhat aggressive

### The clean template issue is not a pipeline bug

It is a model/prompt/policy interpretation issue.

### Stale docs exist

Some older docs mention:

- OpenSearch
- Claude 3.5 Sonnet

The current runtime uses:

- Pinecone
- Sonnet 4 inference profile

Trust the code and `.env` over stale prose.

## 15. Quick-start commands

### Fastest full verification path

```powershell
.venv\Scripts\Activate.ps1
python -c "from config.settings import settings; print(settings.bedrock.model_id, settings.bedrock.embedding_model_id, settings.pinecone.index)"
python -m pytest tests/unit/test_prompt_builder.py tests/unit/test_retrieval_agent.py tests/unit/test_vulnerability_agent.py tests/unit/test_report_generation_agent.py tests/unit/test_embeddings.py -q
python -m pytest tests/integration/test_rag_integration.py tests/integration/test_pipeline_end_to_end.py -q
python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode aws --verbose
python scripts/run_scan.py tests/fixtures/templates/T10_clean_template.yaml --mode aws --verbose
```

## 16. Final takeaway

If you need to explain this project in one paragraph:

This repository implements a multi-agent RAG-based IaC security scanner for CloudFormation templates. It parses the template, retrieves relevant security best practices from a vector store, asks a Bedrock-hosted LLM to identify vulnerabilities and propose remediations, then generates a markdown report saved under `data/reports/generated/`. The project works end-to-end in AWS mode with Pinecone and Sonnet 4, and it includes unit and integration tests for the major layers, though some paper-level capabilities remain simplified and false-positive tuning is still needed.

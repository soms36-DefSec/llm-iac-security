# LLM Agentic Workflow for Automated Vulnerability Detection in IaC

Multi-agent, LLM-driven system for detecting security misconfigurations
in AWS CloudFormation templates.

## Quick Start
```bash
pip install -r requirements.txt
cp .env.example .env          # fill in AWS credentials
make setup-kb                 # initialize knowledge base
make scan TEMPLATE=path/to/template.yaml
make test
```

## Architecture
CloudFormation Template → Parser → RetrievalAgent (RAG/OpenSearch)
  → VulnerabilityDetectionAgent (Claude Sonnet 3.5 v2) → ReportGenerationAgent
  → Markdown Report

## Results (from paper)
- Detection rate: ~85%  |  False positives: ~15%  |  Avg latency: 80-100s

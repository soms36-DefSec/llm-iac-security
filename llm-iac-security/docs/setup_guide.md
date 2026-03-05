# Setup Guide

## Prerequisites
- Python 3.11+
- AWS account with Bedrock access
- Amazon OpenSearch domain

## Steps
1. `git clone <repo> && cd llm-iac-security`
2. `pip install -r requirements.txt`
3. `cp .env.example .env` — fill in your values
4. `python scripts/setup_knowledge_base.py`
5. `python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml`

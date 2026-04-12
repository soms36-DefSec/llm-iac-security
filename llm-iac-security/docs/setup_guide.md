# Setup Guide

## Prerequisites
- Python 3.11+
- AWS account with Bedrock access in `us-west-2`
- AWS credentials configured locally
- Pinecone account with an `iac-security-kb` index

## AWS Configuration
- Region: `us-west-2`
- Claude model / inference profile: `global.anthropic.claude-sonnet-4-20250514-v1:0`
- Embedding model: `amazon.titan-embed-text-v2:0`
- Pinecone index: `iac-security-kb`

Create `.env` from `.env.example` and set:
- `MODE=aws`
- `AWS_REGION=us-west-2`
- `BEDROCK_MODEL_ID=global.anthropic.claude-sonnet-4-20250514-v1:0`
- `BEDROCK_EMBEDDING_MODEL_ID=amazon.titan-embed-text-v2:0`
- `PINECONE_API_KEY=<rotated-key>`
- `PINECONE_INDEX=iac-security-kb`

Leave `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` unset unless you want to
override your existing AWS CLI credentials.

## Steps
1. `git clone <repo-url>`
2. `cd llm-iac-security`
3. `python -m venv .venv`
4. Windows PowerShell: `.venv\Scripts\Activate.ps1`
5. `python -m pip install --upgrade pip`
6. `pip install -r requirements.txt`
7. `Copy-Item .env.example .env`
8. Edit `.env` with your rotated Pinecone API key
9. `aws sts get-caller-identity --region us-west-2`
10. `aws bedrock list-foundation-models --region us-west-2`
11. `python scripts/setup_knowledge_base.py`
12. `python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode aws --verbose`

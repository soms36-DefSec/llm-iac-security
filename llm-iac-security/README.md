# LLM IaC Security Scanner

For the current implementation details, architecture, testing guide, and paper coverage, start here:

- [Implementation and Verification Guide](C:\Users\veldh\Documents\llm-iac-security\llm-iac-security\docs\IMPLEMENTATION_GUIDE.md)

Older sections in this README contain historical setup notes and may not reflect the current Sonnet 4 + Pinecone runtime exactly. Treat `config/settings.py`, `.env`, and the implementation guide as the source of truth.

---

All code changes are complete. Here's the **deployment procedure** for both environments:

---

## Deployment Procedure

### Prerequisites (both environments)
- **Python 3.10+** installed (verify: `python --version`)
- **Git** installed (verify: `git --version`)
- **pip** available (verify: `pip --version`)

### Step 1: Clone and Set Up Virtual Environment
```bash
git clone <your-repo-url>
cd llm-iac-security

# Create and activate virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment
```bash
cp .env.example .env
# Edit .env with your settings (see below for each mode)
```

---

### Environment A: Free/Local Mode (Ollama + ChromaDB + HuggingFace)

**Additional dependencies to install on your machine:**
1. **Ollama** — Download from [ollama.com](https://ollama.com) and install
2. Pull a model:
   ```bash
   ollama pull llama3
   ```
3. Start the Ollama server:
   ```bash
   ollama serve
   ```

**`.env` configuration for local mode:**
```
MODE=local
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
```
- ChromaDB and HuggingFace sentence-transformers are Python packages already in `requirements.txt` — no external services needed
- The HuggingFace embedding model (`all-MiniLM-L6-v2`) downloads automatically on first run (~80MB)
- ChromaDB stores data locally in `.chroma_db/` directory

**Initialize the knowledge base:**
```bash
python scripts/setup_knowledge_base.py
```

**Run a scan:**
```bash
python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode local
```

---

### Environment B: Paid/AWS Mode (Bedrock + Pinecone + Titan Embeddings)

**External services to set up:**
1. **AWS Account** with Bedrock access enabled
   - Enable model access for `Claude 3.5 Sonnet v2` and `Titan Text Embeddings V2` in the AWS Bedrock console
2. **AWS CLI** installed and configured:
   ```bash
   aws configure
   ```
3. **Pinecone account** — Sign up at [pinecone.io](https://pinecone.io) and get an API key

**`.env` configuration for AWS mode:**
```
MODE=aws
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
BEDROCK_EMBEDDING_MODEL_ID=amazon.titan-embed-text-v2:0
PINECONE_API_KEY=your-pinecone-api-key
PINECONE_INDEX=iac-security-kb
```

**Initialize the knowledge base:**
```bash
python scripts/setup_knowledge_base.py
```

**Run a scan:**
```bash
python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode aws
```

---

### Step 4: Verify Installation (both modes)
```bash
# Run all unit tests (no external services needed)
python -m pytest tests/unit/ -v

# Run integration tests (mocked)
python -m pytest tests/integration/ -v

# Run evaluation metrics
python scripts/evaluate_results.py
```

### Step 5: CI/CD Setup (optional)

**GitHub Actions:**
- Copy `cicd/github_actions/iac_security_scan.yml` to `.github/workflows/iac_security_scan.yml`
- Add secrets in GitHub repo settings: `AWS_ROLE_ARN`, `AWS_REGION`, `PINECONE_API_KEY`

**GitLab CI:**
- Copy `cicd/gitlab_ci/.gitlab-ci.yml` to project root as `.gitlab-ci.yml`
- Add CI/CD variables in GitLab settings

**Jenkins:**
- Use `cicd/jenkins/Jenkinsfile` — configure credentials for `aws-credentials` and `pinecone-api-key`

### CLI Usage Summary
```bash
# Basic scan (uses MODE from .env)
python scripts/run_scan.py <template.yaml>

# Override mode via CLI
python scripts/run_scan.py <template.yaml> --mode local
python scripts/run_scan.py <template.yaml> --mode aws

# Custom output path
python scripts/run_scan.py <template.yaml> --output report.md

# Verbose/debug logging
python scripts/run_scan.py <template.yaml> --verbose

# Using Makefile
make scan TEMPLATE=tests/fixtures/templates/T1_basic_s3.yaml MODE=local
make test
make setup-kb
```

---

### Summary of Files Modified/Created

| File | Change |
|------|--------|
| `config/settings.py` | Added `OllamaSettings`, `ChromaSettings`, `LocalEmbeddingSettings`, `is_local` property |
| `config/bedrock_config.py` | Made mode-aware (skips Bedrock init in local mode) |
| `knowledge_base/embeddings.py` | Added `HuggingFaceEmbeddings` class + `get_embeddings()` factory |
| `knowledge_base/vector_store.py` | Added `ChromaVectorStore` class + `get_vector_store()` factory |
| `knowledge_base/kb_manager.py` | Updated to use factory functions |
| `llm/bedrock_client.py` | Added `OllamaClient` class + `get_llm_client()` factory |
| `agents/vulnerability_detection_agent.py` | Uses `get_llm_client()` factory |
| `agents/report_generation_agent.py` | Uses `get_llm_client()` factory |
| `utils/aws_utils.py` | Guards against AWS calls in local mode |
| `scripts/run_scan.py` | Added `--mode`, `--output` flags + error handling |
| `cicd/pipeline_integration.py` | Added mode support |
| `.env.example` | Complete dual-mode configuration template |
| `requirements.txt` | Added `chromadb` dependency |
| `setup.py` | Added `extras_require` for local/aws/dev |
| `Makefile` | Added MODE support and clean target |
| `reporting/report_builder.py` | Fixed deprecation warning |
| CI/CD files | Updated for dual-mode (GitHub Actions, GitLab CI, Jenkinsfile) |
| `tests/` | Updated mock paths for factory functions |
| `tests/fixtures/ground_truth/annotations.json` | Added T7-T10 entries |
| `.gitignore` | Added `.chroma_db/`, `.cache/` |

# LLM IaC Security Scanner — End-to-End Implementation Guide (v2)

> **Scope:** Complete walkthrough — configuration → vulnerable IaC input → RAG retrieval → vulnerability detection → remediation report.
> Covers both **LOCAL mode** (Ollama + ChromaDB) and **AWS mode** (Bedrock + Pinecone).
> Every potential interruption point is called out explicitly.

---

## Table of Contents

1. [How the Pipeline Works — One Page](#1-how-the-pipeline-works--one-page)
2. [Prerequisites](#2-prerequisites)
3. [Project Setup](#3-project-setup)
4. [Configuration Reference](#4-configuration-reference)
   - 4.1 [Local Mode `.env`](#41-local-mode-env)
   - 4.2 [AWS Mode `.env`](#42-aws-mode-env)
5. [Step 1 — Provide a Vulnerable IaC Template](#5-step-1--provide-a-vulnerable-iac-template)
6. [Step 2 — Initialize the Knowledge Base (RAG)](#6-step-2--initialize-the-knowledge-base-rag)
7. [Step 3 — Run the Scan (Full Pipeline)](#7-step-3--run-the-scan-full-pipeline)
8. [Step 4 — Read the Remediation Report](#8-step-4--read-the-remediation-report)
9. [Internal Flow — Annotated Code Paths](#9-internal-flow--annotated-code-paths)
10. [AWS Mode — Extra Setup Steps](#10-aws-mode--extra-setup-steps)
11. [CI/CD Integration](#11-cicd-integration)
12. [Interruption Catalogue — Every Known Failure Point](#12-interruption-catalogue--every-known-failure-point)
13. [Evaluation — Measuring Precision and Recall](#13-evaluation--measuring-precision-and-recall)
14. [Extending the Knowledge Base](#14-extending-the-knowledge-base)
15. [Terraform Support](#15-terraform-support)
16. [Quick Reference Card](#16-quick-reference-card)

---

## 1. How the Pipeline Works — One Page

```
You provide:  vulnerable_template.yaml
                       │
          ┌────────────▼────────────┐
          │  CloudFormationParser   │  parsers/cloudformation_parser.py
          │  parse_and_normalize()  │  → Python dict (resources, properties)
          └────────────┬────────────┘
                       │ normalized_template (dict)
          ┌────────────▼────────────┐
          │   [Agent 1/3]           │  agents/retrieval_agent.py
          │   RetrievalAgent        │
          │                         │
          │  ResourceExtractor      │  parsers/resource_extractor.py
          │  .to_summary_text()     │  → resource_summary (string)
          │         ↓               │
          │  EmbeddingModel         │  knowledge_base/embeddings.py
          │  .embed_text(summary)   │  → 384-dim float vector (local)
          │         ↓               │                  1024-dim (AWS)
          │  VectorStore.search()   │  knowledge_base/vector_store.py
          │  ChromaDB (local)       │  → top-5 best-practice text chunks
          │  Pinecone   (aws)       │
          └────────────┬────────────┘
                       │ rag_snippets (list[str])
                       │ resource_summary (str)   ← stored in context (BUG-04 fix)
          ┌────────────▼────────────┐
          │   [Agent 2/3]           │  agents/vulnerability_detection_agent.py
          │   VulnerabilityDetection│
          │                         │
          │  PromptBuilder          │  llm/prompt_builder.py
          │  .build_vuln_detection()│  → system_prompt + user_prompt
          │         ↓               │    (template summary + RAG context)
          │  BedrockClient.invoke() │  llm/bedrock_client.py
          │  Ollama /api/chat       │  → raw LLM response (JSON string)
          │  Bedrock Converse API   │
          │         ↓               │
          │  parse_vuln_response()  │  llm/response_parser.py
          │  validate + deduplicate │  → findings dict
          └────────────┬────────────┘
                       │ findings (dict with vulnerabilities list)
          ┌────────────▼────────────┐
          │   [Agent 3/3]           │  agents/report_generation_agent.py
          │   ReportGenerationAgent │
          │                         │
          │  MarkdownFormatter      │  reporting/markdown_formatter.py
          │  .format(findings)      │  → Markdown report string
          └────────────┬────────────┘
                       │ report_markdown (str)
          ┌────────────▼────────────┐
          │   ReportBuilder.save()  │  reporting/report_builder.py
          │   disk + optional S3    │  → data/reports/generated/*.md
          └─────────────────────────┘

OUTPUT: Markdown security report with severity-sorted findings + remediation steps
```

---

## 2. Prerequisites

### Local Mode

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.10+ | Runtime |
| Ollama | any | Local LLM server |
| A pulled Ollama model | `llama3`, `mistral`, `phi3` | The LLM that detects vulnerabilities |

```bash
# Install Ollama (Windows/macOS/Linux)
# https://ollama.com/download

# Pull a model — llama3 recommended for best JSON compliance
ollama pull llama3

# Verify it's running
ollama serve          # in a separate terminal (or it runs as a service)
curl http://localhost:11434/api/tags
```

> **⚠ INTERRUPT — Model JSON quality:**
> Not all Ollama models reliably produce valid JSON. `llama3` and `mistral` work well.
> `phi3:mini` tends to skip the JSON wrapper. If you get 0 findings, switch to `llama3`.

### AWS Mode

| Requirement | Notes |
|-------------|-------|
| AWS account | Bedrock + S3 access |
| Bedrock model access | Must request access in AWS console for Claude Sonnet 3.5 v2 |
| Pinecone account | Free tier sufficient for < 100K vectors |
| AWS CLI | Configured with a profile or access keys |

### Both Modes

```bash
# Python packages
pip install -r requirements.txt
```

---

## 3. Project Setup

```bash
# 1. Clone / navigate to project
cd llm-iac-security

# 2. Create virtual environment (recommended)
python -m venv env
env\Scripts\activate          # Windows
source env/bin/activate        # macOS/Linux

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Verify imports are clean
python -c "from orchestrator.pipeline import IaCSecurityPipeline; print('OK')"
```

> **⚠ INTERRUPT — sentence-transformers on first run:**
> The first `pip install` downloads `torch` + `sentence-transformers` (~1.5 GB).
> On restricted networks this will time out. Use `pip install --timeout 120 -r requirements.txt`.

---

## 4. Configuration Reference

Create a `.env` file in the project root. The scanner loads it automatically via `python-dotenv`.

### 4.1 Local Mode `.env`

```dotenv
# ─── MODE ─────────────────────────────────────────────────────────────────────
MODE=local

# ─── OLLAMA ───────────────────────────────────────────────────────────────────
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3                    # or mistral, phi3, llama3.1, etc.

# ─── LOCAL VECTOR STORE (ChromaDB) ───────────────────────────────────────────
CHROMA_PERSIST_DIR=data/chroma_db      # where ChromaDB stores its files

# ─── LOCAL EMBEDDING MODEL (HuggingFace) ─────────────────────────────────────
LOCAL_EMBED_MODEL=all-MiniLM-L6-v2     # downloaded on first use (~80 MB)

# ─── KNOWLEDGE BASE ───────────────────────────────────────────────────────────
KB_SOURCES_DIR=knowledge_base/sources  # directory containing .md/.pdf/.txt docs

# ─── RAG TUNING ───────────────────────────────────────────────────────────────
CHUNK_SIZE=512                         # characters per KB chunk
CHUNK_OVERLAP=50                       # overlap between chunks
TOP_K_RESULTS=5                        # snippets injected per prompt
SIMILARITY_THRESHOLD=0.3               # minimum cosine similarity to include snippet
MAX_RAG_CONTEXT_CHARS=2048             # total RAG text budget in prompt

# ─── LLM TUNING ───────────────────────────────────────────────────────────────
MAX_TOKENS=4096
LLM_TIMEOUT_SECONDS=120
MAX_LLM_RETRIES=3

# ─── OUTPUT ───────────────────────────────────────────────────────────────────
REPORTS_OUTPUT_DIR=data/reports/generated
LOG_LEVEL=INFO                         # DEBUG for verbose agent traces
```

### 4.2 AWS Mode `.env`

```dotenv
# ─── MODE ─────────────────────────────────────────────────────────────────────
MODE=aws

# ─── AWS CREDENTIALS ──────────────────────────────────────────────────────────
AWS_REGION=us-east-1
# Option A — named profile (recommended)
AWS_PROFILE=your-aws-profile
# Option B — access keys (avoid in production)
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...

# ─── BEDROCK ──────────────────────────────────────────────────────────────────
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
BEDROCK_EMBED_MODEL_ID=amazon.titan-embed-text-v2:0

# ─── PINECONE ─────────────────────────────────────────────────────────────────
PINECONE_API_KEY=pcsk_xxxxxxxxxxxx
PINECONE_INDEX=iac-security-kb         # created automatically on first run

# ─── KNOWLEDGE BASE ───────────────────────────────────────────────────────────
KB_SOURCES_DIR=knowledge_base/sources

# ─── RAG TUNING ───────────────────────────────────────────────────────────────
CHUNK_SIZE=512
CHUNK_OVERLAP=50
TOP_K_RESULTS=5
SIMILARITY_THRESHOLD=0.3
MAX_RAG_CONTEXT_CHARS=2048

# ─── LLM TUNING ───────────────────────────────────────────────────────────────
MAX_TOKENS=4096
LLM_TIMEOUT_SECONDS=120
MAX_LLM_RETRIES=3

# ─── S3 REPORT STORAGE ────────────────────────────────────────────────────────
S3_REPORTS_BUCKET=your-iac-security-reports-bucket
S3_TEMPLATES_BUCKET=your-iac-templates-bucket

# ─── OUTPUT ───────────────────────────────────────────────────────────────────
REPORTS_OUTPUT_DIR=data/reports/generated
LOG_LEVEL=INFO
```

---

## 5. Step 1 — Provide a Vulnerable IaC Template

The scanner accepts **CloudFormation** (`.yaml` / `.json`) and **Terraform** (`.tf`).
Place your template anywhere on disk and pass its path to the CLI.

### 5.1 Example Vulnerable Templates

Below are four worked examples identical to the project's test fixtures. Each has deliberately introduced misconfigurations so you can see real scanner output.

---

#### Template A — S3 Misconfigurations (`my_s3.yaml`)

```yaml
# VULNERABILITIES IN THIS TEMPLATE:
# 1. PublicAccessBlock all flags = false  → CRITICAL (data exposed to internet)
# 2. No BucketEncryption                  → HIGH    (data at rest unencrypted)
# 3. No VersioningConfiguration           → MEDIUM  (no point-in-time recovery)
# 4. No LoggingConfiguration              → LOW     (no audit trail)

AWSTemplateFormatVersion: "2010-09-09"
Description: "Insecure S3 bucket — for scanner testing"

Resources:
  MyS3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-insecure-bucket
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: false
        IgnorePublicAcls: false
        RestrictPublicBuckets: false
      # Missing: BucketEncryption
      # Missing: VersioningConfiguration
      # Missing: LoggingConfiguration
```

**Expected detections:** 3–4 findings (CRITICAL, HIGH, MEDIUM, LOW)

---

#### Template B — IAM Privilege Escalation (`my_iam.yaml`)

```yaml
# VULNERABILITIES IN THIS TEMPLATE:
# 1. Principal: "*" on AssumeRole       → CRITICAL (any AWS account can assume)
# 2. Action: "*" Resource: "*"          → CRITICAL (full admin access)
# 3. iam:PassRole + iam:CreateRole      → HIGH    (privilege escalation path)

AWSTemplateFormatVersion: "2010-09-09"
Description: "Overly permissive IAM roles — for scanner testing"

Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"               # CRITICAL: any entity can assume
            Action: "sts:AssumeRole"
      Policies:
        - PolicyName: AdminPolicy
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: "*"              # CRITICAL: wildcard action
                Resource: "*"            # CRITICAL: wildcard resource

  EscalationPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - "iam:PassRole"           # HIGH: can escalate privileges
              - "iam:CreateRole"
              - "sts:AssumeRole"
            Resource: "*"
```

**Expected detections:** 3–4 findings (CRITICAL × 2, HIGH × 1–2)

---

#### Template C — Open Security Groups (`my_sg.yaml`)

```yaml
# VULNERABILITIES IN THIS TEMPLATE:
# 1. SSH (port 22) from 0.0.0.0/0       → CRITICAL (internet SSH access)
# 2. RDP (port 3389) from 0.0.0.0/0     → CRITICAL (internet RDP access)
# 3. MySQL (port 3306) from 0.0.0.0/0   → CRITICAL (internet DB access)
# 4. All egress allowed                  → LOW     (data exfiltration risk)

AWSTemplateFormatVersion: "2010-09-09"
Description: "Open security groups — for scanner testing"

Resources:
  OpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Intentionally open security group
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0             # CRITICAL: SSH open to internet

        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0             # CRITICAL: RDP open to internet

        - IpProtocol: tcp
          FromPort: 3306
          ToPort: 3306
          CidrIp: 0.0.0.0/0             # CRITICAL: MySQL open to internet

      SecurityGroupEgress:
        - IpProtocol: "-1"              # All protocols
          CidrIp: 0.0.0.0/0             # All destinations
```

**Expected detections:** 3–4 findings (CRITICAL × 3, LOW × 1)

---

#### Template D — Insecure RDS (`my_rds.yaml`)

```yaml
# VULNERABILITIES IN THIS TEMPLATE:
# 1. StorageEncrypted: false            → CRITICAL (DB data unencrypted)
# 2. PubliclyAccessible: true           → CRITICAL (DB exposed to internet)
# 3. BackupRetentionPeriod: 0           → HIGH    (no automated backups)
# 4. DeletionProtection: false          → MEDIUM  (can be deleted accidentally)
# 5. MultiAZ: false                     → MEDIUM  (no HA/failover)

AWSTemplateFormatVersion: "2010-09-09"
Description: "Insecure RDS instance — for scanner testing"

Parameters:
  DBPassword:
    Type: String
    NoEcho: true
    Default: insecure-placeholder       # HIGH: weak default password

Resources:
  InsecureRDS:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      EngineVersion: "8.0"
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword
      StorageEncrypted: false           # CRITICAL
      PubliclyAccessible: true          # CRITICAL
      BackupRetentionPeriod: 0          # HIGH: backups disabled
      DeletionProtection: false         # MEDIUM
      MultiAZ: false                    # MEDIUM
      AllocatedStorage: "20"
```

**Expected detections:** 4–5 findings (CRITICAL × 2, HIGH × 1, MEDIUM × 2)

---

#### Template E — Multi-Resource (`my_mixed.yaml`)

```yaml
# VULNERABILITIES IN THIS TEMPLATE:
# Cross-resource misconfigurations — tests multi-resource detection

AWSTemplateFormatVersion: "2010-09-09"
Description: "Multi-resource vulnerable template"

Resources:
  BadBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: bad-bucket
      # Missing: PublicAccessBlock, BucketEncryption, Versioning

  WildcardRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: "sts:AssumeRole"

  OpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Open
      SecurityGroupIngress:
        - IpProtocol: "-1"              # All protocols from anywhere
          CidrIp: 0.0.0.0/0

  UnencryptedDB:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      StorageEncrypted: false
      PubliclyAccessible: true
```

**Expected detections:** 6–8 findings across all resource types

---

### 5.2 Where to Place Templates

```
llm-iac-security/
├── my_templates/              ← create this directory
│   ├── my_s3.yaml
│   ├── my_iam.yaml
│   ├── my_sg.yaml
│   ├── my_rds.yaml
│   └── my_mixed.yaml
└── tests/fixtures/templates/  ← built-in test fixtures (T1–T10)
    ├── T1_basic_s3.yaml
    ├── T2_iam_roles.yaml
    └── ...
```

---

## 6. Step 2 — Initialize the Knowledge Base (RAG)

This step chunks, embeds, and indexes all security best-practice documents into the vector store. **This must be done once before the first scan**, and re-run whenever you add new KB documents.

### 6.1 What's Already in the KB

```
knowledge_base/sources/
├── aws_well_architected.md       # AWS Well-Architected pillars
├── aws_secrets_manager.md        # Secrets Manager usage
├── cis_benchmarks.md             # CIS AWS Foundations Benchmark
├── iam_best_practices.md         # IAM least-privilege
├── s3_security.md                # S3 encryption, public access, versioning
├── security_groups.md            # SG ingress/egress rules
├── rds_security.md               # RDS encryption, public access, backups
├── lambda_security.md            # Lambda roles, VPC, secrets
└── cloudtrail_monitoring.md      # CloudTrail, GuardDuty, monitoring
```

### 6.2 Run KB Initialization

```bash
# LOCAL MODE
python scripts/setup_knowledge_base.py

# AWS MODE — ensure .env has PINECONE_API_KEY set
MODE=aws python scripts/setup_knowledge_base.py
```

**What this does internally:**

```
setup_knowledge_base.py
  └── KnowledgeBaseManager.initialize(force_rebuild=True)
        └── KnowledgeBaseManager.load_all_sources()
              ├── For each .md / .pdf / .txt in KB_SOURCES_DIR:
              │     ├── Read file text
              │     ├── _chunk_text(text, size=512, overlap=50)
              │     │     → e.g., 9 docs × ~15 chunks = ~135 vectors
              │     ├── EmbeddingModel.embed_batch(chunks)
              │     │     LOCAL: SentenceTransformer.encode() → 384-dim
              │     │     AWS:   Titan Text Embeddings V2  → 1024-dim
              │     └── VectorStore.upsert(chunk_id, text, vector, metadata)
              │           LOCAL: ChromaDB PersistentClient
              │           AWS:   Pinecone serverless upsert
              └── Logs: "Document indexed: doc_id=s3_security chunks=14"
```

**Expected output:**

```
[KB Setup] Loading sources from knowledge_base/sources/ ...
[KB Setup] Indexed: aws_well_architected (12 chunks)
[KB Setup] Indexed: cis_benchmarks (18 chunks)
[KB Setup] Indexed: iam_best_practices (11 chunks)
[KB Setup] Indexed: s3_security (14 chunks)
[KB Setup] Indexed: security_groups (13 chunks)
[KB Setup] Indexed: rds_security (15 chunks)
[KB Setup] Indexed: lambda_security (12 chunks)
[KB Setup] Indexed: cloudtrail_monitoring (14 chunks)
[KB Setup] Total: 9 documents, ~135 chunks indexed.
```

> **⚠ INTERRUPT — First run downloads embedding model:**
> HuggingFace `all-MiniLM-L6-v2` (~80 MB) is downloaded automatically on first run.
> No internet = no model. Solution: pre-download with `python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"` while online, then run offline.

> **⚠ INTERRUPT — Pinecone index creation delay (AWS mode):**
> Pinecone creates the index asynchronously. The first `initialize()` call may take 30–90 seconds while the index becomes ready. The code waits automatically. If it times out, re-run — the index will already exist.

---

## 7. Step 3 — Run the Scan (Full Pipeline)

### 7.1 Basic Scan

```bash
# Scan a single template (local mode, default settings)
python scripts/run_scan.py my_templates/my_s3.yaml

# Scan with verbose logging (shows per-agent progress)
python scripts/run_scan.py my_templates/my_rds.yaml --verbose

# Specify output report path
python scripts/run_scan.py my_templates/my_sg.yaml --output reports/sg_scan.md

# Override mode at runtime
python scripts/run_scan.py my_templates/my_iam.yaml --mode aws

# Retrieve more KB snippets per scan
python scripts/run_scan.py my_templates/my_mixed.yaml --top-k 8
```

### 7.2 What You See in the Terminal

```
╔══════════════════════════════════════════════════════╗
║      LLM IaC Security Scanner  v1.0.0               ║
╚══════════════════════════════════════════════════════╝

 Mode:      local (Ollama + ChromaDB)
 Template:  my_templates/my_s3.yaml
 Output:    data/reports/generated/20260405_153022_my_s3.md

[1/3] RetrievalAgent ......................................... done (1.2s)
[2/3] VulnerabilityDetectionAgent ........................... done (8.4s)
[3/3] ReportGenerationAgent ................................. done (0.1s)

──────────────────────────────────────────────────────
 SCAN COMPLETE — 3 findings in 9.8 seconds

  CRITICAL   1
  HIGH       1
  MEDIUM     1
  LOW        0

 Report saved to: data/reports/generated/20260405_153022_my_s3.md
──────────────────────────────────────────────────────
```

### 7.3 AWS Mode Scan

```bash
# Ensure .env has MODE=aws and all AWS credentials set
python scripts/run_scan.py my_templates/my_s3.yaml --mode aws --verbose
```

---

## 8. Step 4 — Read the Remediation Report

Reports are saved as Markdown at `data/reports/generated/`. Example output for `my_s3.yaml`:

---

```markdown
# Security Scan Report: `my_s3`

## Summary
3 misconfigurations detected across 1 resource. 1 CRITICAL issue requires immediate attention.

**Total findings:** 3

- 🔴 **CRITICAL**: 1
- 🟠 **HIGH**: 1
- 🟡 **MEDIUM**: 1

---

## Findings Overview

| Severity | Resource | Vulnerability Type |
|:---------|:---------|:-------------------|
| 🔴 CRITICAL | `MyS3Bucket` | Public access enabled |
| 🟠 HIGH | `MyS3Bucket` | No server-side encryption |
| 🟡 MEDIUM | `MyS3Bucket` | S3 versioning disabled |

---

## Detailed Findings

### 1. 🔴 Public access enabled
**Resource:** `MyS3Bucket` (AWS::S3::Bucket) | **Severity:** CRITICAL

**Description:**
All four `PublicAccessBlockConfiguration` flags are set to `false`, meaning the bucket
can be made publicly accessible via bucket policies or ACLs. This exposes all stored
objects to potential public read/write access.

**Remediation:**
Set all four flags to `true` in your CloudFormation template:
```yaml
PublicAccessBlockConfiguration:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: true
```

**Reference:** CIS AWS Foundations Benchmark 2.1.5

---

### 2. 🟠 No server-side encryption
**Resource:** `MyS3Bucket` (AWS::S3::Bucket) | **Severity:** HIGH

**Description:**
The bucket has no `BucketEncryption` property configured. Data written to this bucket
is stored unencrypted at rest, violating data protection requirements.

**Remediation:**
Add encryption configuration (prefer aws:kms for audit trail):
```yaml
BucketEncryption:
  ServerSideEncryptionConfiguration:
    - ServerSideEncryptionByDefault:
        SSEAlgorithm: aws:kms
```

**Reference:** AWS Well-Architected Security Pillar SEC-8

---

### 3. 🟡 S3 versioning disabled
**Resource:** `MyS3Bucket` (AWS::S3::Bucket) | **Severity:** MEDIUM

**Description:**
No `VersioningConfiguration` is present. Without versioning, overwritten or deleted
objects cannot be recovered, creating a data loss risk.

**Remediation:**
```yaml
VersioningConfiguration:
  Status: Enabled
```

**Reference:** CIS AWS Foundations Benchmark 2.1.3
```

---

## 9. Internal Flow — Annotated Code Paths

### 9.1 Template Parsing

```
run_scan.py:main()
  → IaCSecurityPipeline.__init__()           orchestrator/pipeline.py:18
      → settings.validate_config()           config/settings.py:88
  → pipeline.run(template_path)              orchestrator/pipeline.py:44
      → validate_template_path(path)         utils/validation.py:6
      → _get_parser(path)                    orchestrator/pipeline.py:34
          CloudFormationParser()  if .yaml/.json
          TerraformParser()       if .tf
      → parser.parse_and_normalize(path)
          .parse()   → raw dict (yaml.safe_load / json.loads / hcl2.load)
          .normalize() → {template_format_version, resources, parameters, outputs}
```

### 9.2 RAG Retrieval (Agent 1)

```
RetrievalAgent.run(context)                  agents/retrieval_agent.py:19
  → ResourceExtractor(normalized).to_summary_text()
      → builds string like:
         "<template_content>
          Resource: MyS3Bucket (Type: AWS::S3::Bucket)
            BucketName: my-insecure-bucket
            PublicAccessBlockConfiguration: {'BlockPublicAcls': False ...}
          </template_content>"
  → stored as context["resource_summary"]    ← avoids re-computation in Agent 2

  → KnowledgeBaseManager.retrieve(resource_summary)
      → EmbeddingModel.embed_text(resource_summary)
          LOCAL: SentenceTransformer.encode()    → float list [384 dims]
          AWS:   Bedrock Titan embed_text()       → float list [1024 dims]
          CACHE: LocalCache("embeddings").get(text) checked first
      → VectorStore.search(query_vector, top_k=5)
          LOCAL: ChromaDB collection.query()
          AWS:   Pinecone index.query()
          FILTER: score < SIMILARITY_THRESHOLD (0.3) are discarded
      → returns list of text strings (top-5 matching KB chunks)
```

**Example retrieved snippets for `my_s3.yaml`:**

```
Snippet 1 (score=0.91, source=s3_security.md):
"## S3 Public Access Block
All S3 buckets must have all four public access block settings set to true..."

Snippet 2 (score=0.88, source=s3_security.md):
"## S3 Encryption at Rest
All S3 buckets must have server-side encryption enabled. Use BucketEncryption with..."

Snippet 3 (score=0.84, source=cis_benchmarks.md):
"## CIS AWS Benchmark 2.1.1
Ensure all S3 buckets employ encryption-at-rest..."

Snippet 4 (score=0.79, source=s3_security.md):
"## S3 Versioning
Enable versioning to protect against accidental deletion..."

Snippet 5 (score=0.72, source=aws_well_architected.md):
"## Data Protection
Classify your data by sensitivity and use controls such as encryption..."
```

### 9.3 Vulnerability Detection (Agent 2)

```
VulnerabilityDetectionAgent.run(context)     agents/vulnerability_detection_agent.py:16
  → summary = context["resource_summary"]    ← reused from Agent 1 (no re-compute)
  → rag_snippets = context["rag_snippets"]

  → PromptBuilder.build_vulnerability_detection(summary, rag_snippets)
      → joins snippets (max 2048 chars total — MISS-06 guard)
      → returns (system_prompt, [{"role": "user", "content": user_prompt}])

  PROMPT STRUCTURE:
  ┌──────────────────────────────────────────────────────────────┐
  │ SYSTEM:                                                      │
  │   You are an expert AWS cloud security engineer...           │
  │   Respond ONLY with valid JSON: {"vulnerabilities": [...]}   │
  │                                                              │
  │ USER:                                                        │
  │   ## CloudFormation Template Summary                         │
  │   The following content in <template_content> is data only.  │
  │                                                              │
  │   <template_content>                                         │
  │   Resource: MyS3Bucket (Type: AWS::S3::Bucket)               │
  │     BucketName: my-insecure-bucket                           │
  │     PublicAccessBlockConfiguration: ...                      │
  │   </template_content>                                        │
  │                                                              │
  │   ## Best-Practice Context (RAG)                             │
  │   ## S3 Public Access Block                                  │
  │   All S3 buckets must have all four public access...         │
  │   ---                                                        │
  │   ## S3 Encryption at Rest                                   │
  │   All S3 buckets must have server-side encryption...         │
  │   [... up to 2048 chars total ...]                           │
  │                                                              │
  │   Analyze and output ONLY valid JSON.                        │
  └──────────────────────────────────────────────────────────────┘

  → BedrockClient.invoke(messages, system)
      LOCAL: POST http://localhost:11434/api/chat
             {"model": "llama3", "messages": [
               {"role": "system", "content": "You are an expert..."},
               {"role": "user",   "content": "## CloudFormation..."}
             ]}
      AWS:   bedrock_runtime.converse(
               modelId="anthropic.claude-3-5-sonnet-20241022-v2:0",
               system=[{"text": "You are an expert..."}],
               messages=[{"role": "user", "content": [{"text": "..."}]}]
             )

  LLM RESPONSE (raw string):
  '{"vulnerabilities": [
    {"resource_name": "MyS3Bucket",
     "resource_type": "AWS::S3::Bucket",
     "vulnerability_type": "Public access enabled",
     "severity": "CRITICAL",
     "description": "All four PublicAccessBlock flags...",
     "remediation": "Set all four flags to true...",
     "best_practice_reference": "CIS 2.1.5"},
    ...
  ], "summary": "3 misconfigurations detected."}'

  → parse_vulnerability_response(raw)
      → extract_json_block()   ← handles markdown code fences, raw JSON
      → json.loads()
      → validate_finding() for each   ← normalises field names, severity
      → _deduplicate_findings()       ← drops (resource_name, vuln_type) dupes
```

### 9.4 Report Generation (Agent 3)

```
ReportGenerationAgent.run(context)           agents/report_generation_agent.py:17
  → findings = context["findings"]

  → MarkdownFormatter.format(findings, template_name)
      → SeverityClassifier.sort_findings()  → CRITICAL first
      → builds:
          # Security Scan Report: `my_s3`
          ## Summary
          ## Findings Overview  (table)
          ## Detailed Findings  (one section per finding)
      → returns markdown string

  → context["report_markdown"] = markdown

ReportBuilder.save(markdown, template_name)  reporting/report_builder.py
  → writes to REPORTS_OUTPUT_DIR/timestamp_name.md
  → if MODE=aws and S3_REPORTS_BUCKET set:
       S3Handler.upload_report(path)         storage/s3_handler.py
```

---

## 10. AWS Mode — Extra Setup Steps

### 10.1 Enable Bedrock Model Access

```
AWS Console → Amazon Bedrock → Model access → Request access:
  ✓ Anthropic Claude 3.5 Sonnet v2
  ✓ Amazon Titan Text Embeddings V2

Wait for approval (usually instant for Claude Sonnet, up to 1 hour for Titan).
```

> **⚠ INTERRUPT — Model access not approved:**
> If you get `AccessDeniedException: You don't have access to the model`, you have
> not been granted access. Request it in the Bedrock console. Each region requires
> separate access requests.

### 10.2 Create Pinecone Index (Auto-created)

The scanner auto-creates the Pinecone index on first `initialize()`. You only need the API key:

```bash
# Get free API key at https://www.pinecone.io
# Add to .env:
PINECONE_API_KEY=pcsk_xxxxxxxxxxxx
PINECONE_INDEX=iac-security-kb      # name is arbitrary
```

The index is created with:
- **Dimension:** 1024 (Titan Text Embeddings V2 output size)
- **Metric:** cosine
- **Cloud:** AWS, region matching `AWS_REGION`

> **⚠ INTERRUPT — Pinecone free tier limit:**
> Free tier allows 1 index and ~100K vectors. With ~135 chunks this is fine.
> If you hit limits: delete old vectors with `KnowledgeBaseManager._store.clear()`.

### 10.3 Create S3 Buckets

```bash
# Create report storage bucket
aws s3 mb s3://your-iac-security-reports-bucket --region us-east-1

# Create template storage bucket (optional — only needed for S3-sourced templates)
aws s3 mb s3://your-iac-templates-bucket --region us-east-1
```

### 10.4 Required IAM Permissions

The IAM user or role running the scanner needs these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:Converse"
      ],
      "Resource": [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
        "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::your-iac-security-reports-bucket",
        "arn:aws:s3:::your-iac-security-reports-bucket/*"
      ]
    }
  ]
}
```

Pinecone authentication is via API key (not IAM), so no Pinecone-specific IAM policy is needed.

---

## 11. CI/CD Integration

### 11.1 GitHub Actions

```yaml
# .github/workflows/iac_security_scan.yml
name: IaC Security Scan

on:
  pull_request:
    paths: ['infrastructure/**/*.yaml', 'infrastructure/**/*.tf']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Setup KB (cache between runs)
        run: python scripts/setup_knowledge_base.py
        env:
          MODE: local
          OLLAMA_HOST: http://localhost:11434
          OLLAMA_MODEL: llama3

      - name: Run IaC security scan
        run: |
          python cicd/pipeline_integration.py \
            infrastructure/my_stack.yaml \
            --min-severity HIGH        # fail only on HIGH+ findings
        env:
          MODE: local
          OLLAMA_HOST: http://localhost:11434
```

### 11.2 Severity Gate Options

```bash
# Fail on ANY real finding (excludes INFO)
python cicd/pipeline_integration.py template.yaml --min-severity LOW

# Fail only on HIGH and CRITICAL (recommended for production gates)
python cicd/pipeline_integration.py template.yaml --min-severity HIGH

# Fail only on CRITICAL findings (strictest — deploy pipeline)
python cicd/pipeline_integration.py template.yaml --min-severity CRITICAL
```

Exit codes: `0` = passed gate, `1` = blocked findings found.

---

## 12. Interruption Catalogue — Every Known Failure Point

This section documents every place the pipeline can fail, the error you will see, and how to fix it.

---

### INT-01 — Ollama not running

**When:** Agent 2 tries to call `http://localhost:11434/api/chat`

**Error:**
```
LLMError: Cannot connect to Ollama at http://localhost:11434.
Ensure 'ollama serve' is running.
```

**Fix:**
```bash
ollama serve         # in a separate terminal
# or on macOS: it auto-starts when you pull a model
```

---

### INT-02 — Ollama model not pulled

**When:** Agent 2 sends request; Ollama returns HTTP 404

**Error:**
```
LLMError: Ollama returned HTTP 404: {"error":"model 'llama3' not found..."}
```

**Fix:**
```bash
ollama pull llama3   # or whatever OLLAMA_MODEL is set to
```

---

### INT-03 — LLM returns non-JSON output

**When:** The model ignores the JSON instruction and responds in prose.

**Symptom:** 0 findings, sentinel "No misconfigurations detected" in report, even for templates with obvious vulnerabilities.

**Log message:**
```
WARNING: Failed to parse LLM response as JSON. Returning empty list.
```

**Fixes:**
1. Switch to a more instruction-following model: `OLLAMA_MODEL=llama3` or `OLLAMA_MODEL=mistral`
2. Add `--verbose` to see what the LLM actually returned
3. Reduce temperature: ensure `temperature=0.1` (already default)
4. If using a small model (phi3:mini), it may not support strict JSON. Use a 7B+ parameter model.

---

### INT-04 — KB empty / retrieval returns 0 snippets

**When:** Agent 1 finds no vectors in ChromaDB/Pinecone.

**Symptom:** RAG context shows "No context retrieved." — LLM has no best-practice grounding.

**Log message:**
```
INFO: retrieved_snippets count=0
```

**Fix:**
```bash
# KB was never initialized or was cleared
python scripts/setup_knowledge_base.py

# Force rebuild if already initialized
python -c "
from knowledge_base.kb_manager import KnowledgeBaseManager
kb = KnowledgeBaseManager()
kb.initialize(force_rebuild=True)
print('Rebuilt. Count:', kb._store.document_count())
"
```

---

### INT-05 — Similarity threshold too high (0 results despite populated KB)

**When:** All KB chunks score below `SIMILARITY_THRESHOLD=0.3` for the query.

**Symptom:** Same as INT-04: 0 snippets retrieved.

**Diagnosis:**
```python
# Run this to see actual scores
from knowledge_base.kb_manager import KnowledgeBaseManager
kb = KnowledgeBaseManager()
kb.initialize()
results = kb.query("S3 public access encryption vulnerability")
for r in results:
    print(r["score"], r["metadata"]["source"])
```

**Fix:** Lower the threshold in `.env`:
```dotenv
SIMILARITY_THRESHOLD=0.2    # or 0.15 for more permissive retrieval
```

---

### INT-06 — validate_config() fails at startup

**When:** `MODE=aws` but required variables are missing.

**Error:**
```
Configuration error: Missing required configuration for MODE='aws':
OPENSEARCH_ENDPOINT or PINECONE_API_KEY
```

**Fix:** Ensure `.env` has `PINECONE_API_KEY=...` set (not empty).

---

### INT-07 — Bedrock AccessDeniedException

**When:** Running in AWS mode without model access approved.

**Error:**
```
LLMError: Bedrock invocation failed: An error occurred (AccessDeniedException):
You don't have access to the model with the specified model ID.
```

**Fix:** Request model access in AWS Console → Bedrock → Model access.

---

### INT-08 — Bedrock ThrottlingException

**When:** Too many Bedrock requests in a short period (dev/free tier accounts).

**Error:** Now caught as `LLMRateLimitError` and retried automatically (up to `MAX_LLM_RETRIES=3`).

**If retries exhausted:**
```
LLMError: LLM call failed after 3 attempts. Last error: LLMRateLimitError: Bedrock throttled
```

**Fix:** Increase `MAX_LLM_RETRIES=5` or add `LLM_TIMEOUT_SECONDS=180` to `.env`.

---

### INT-09 — Pinecone index not ready

**When:** First-ever `initialize()` with Pinecone; index is still being created.

**Error:**
```
KnowledgeBaseError: Pinecone index 'iac-security-kb' not ready. Retry in 30s.
```

**Fix:** Re-run `setup_knowledge_base.py`. The index will be ready on the second attempt.

---

### INT-10 — sentence-transformers download fails (no internet)

**When:** First run, HuggingFace model not cached.

**Error:**
```
KnowledgeBaseError: Failed to initialise embedding model (mode=local):
Connection error downloading all-MiniLM-L6-v2
```

**Fix:** Pre-download on an internet-connected machine:
```bash
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
# Model cached at: ~/.cache/torch/sentence_transformers/
```

---

### INT-11 — Terraform parsing fails (complex HCL)

**When:** `.tf` file uses Terraform modules, `for_each`, dynamic blocks, or variable interpolation.

**Error:**
```
ParsingError: Failed to parse Terraform file main.tf: ...
```

**Partial fix:** The Terraform parser handles flat `resource {}` blocks. Complex files with `module {}`, `for_each`, or `${var.x}` references will either fail or produce incomplete property extraction.

**Workaround:** Flatten your Terraform first with `terraform show -json` and pass the JSON to a custom script, or use CloudFormation equivalents for now.

---

### INT-12 — Windows ChromaDB file lock on test cleanup

**When:** Running integration tests on Windows; ChromaDB holds open handles.

**Error (teardown):**
```
PermissionError: [WinError 32] The process cannot access the file because it is being used by another process
```

**Status:** Fixed — `shutil.rmtree(tmpdir, ignore_errors=True)` in `test_rag_integration.py`.
This is a Windows-only issue and does not affect production scans.

---

### INT-13 — Report shows only sentinel finding

**Symptom:** Every template produces exactly one finding:
```
Vulnerability: No misconfigurations detected
Severity: INFO
```

**Root cause chain:**
1. LLM returns non-JSON → `parse_vulnerability_response()` returns `[]`
2. Empty list triggers sentinel injection in Agent 2
3. All templates appear clean even when they're not

**Diagnosis steps:**
```bash
# 1. Run with verbose logging
python scripts/run_scan.py my_rds.yaml --verbose

# 2. Check what the LLM actually said
# Add this temporarily to vulnerability_detection_agent.py line 27:
# print("RAW LLM OUTPUT:", raw[:500])

# 3. Check KB is populated
python -c "
from knowledge_base.kb_manager import KnowledgeBaseManager
kb = KnowledgeBaseManager(); kb.initialize()
print('KB chunks:', kb._store.document_count())
"
```

---

## 13. Evaluation — Measuring Precision and Recall

After running scans on T1–T5 test templates, measure detection quality:

```bash
# Run scans on all test fixtures first
for t in tests/fixtures/templates/T1_basic_s3.yaml \
          tests/fixtures/templates/T2_iam_roles.yaml \
          tests/fixtures/templates/T3_security_groups.yaml \
          tests/fixtures/templates/T4_rds_encrypted.yaml \
          tests/fixtures/templates/T5_multi_resource.yaml; do
    python scripts/run_scan.py $t
done

# Run evaluation
python scripts/evaluate_results.py
```

**What the evaluator does:**

```
evaluate_results.py
  → Loads tests/fixtures/ground_truth/annotations.json  (20 known vulnerabilities)
  → Loads all reports in REPORTS_OUTPUT_DIR
  → For each template T1–T5:
       detected = set of (resource_name, vulnerability_type) pairs from report
       expected = set from annotations.json
       precision = |detected ∩ expected| / |detected|
       recall    = |detected ∩ expected| / |expected|
       f1        = 2 × (p × r) / (p + r)
  → Saves metrics to data/reports/evaluation_<timestamp>.json
```

**Target scores (per paper):**

| Template | Expected Findings | Target Recall |
|----------|-------------------|---------------|
| T1 (S3) | 3 | ≥ 80% |
| T2 (IAM) | 4 | ≥ 80% |
| T3 (Security Groups) | 3 | ≥ 80% |
| T4 (RDS) | 5 | ≥ 80% |
| T5 (Multi) | 5 | ≥ 75% |

**If recall is 0% for all templates:** See INT-03 and INT-04. KB is empty or LLM is not producing JSON.

---

## 14. Extending the Knowledge Base

### 14.1 Add a New Security Document

```bash
# Create a new KB doc
cat > knowledge_base/sources/kms_security.md << 'EOF'
# AWS KMS Key Management Best Practices

## Key Rotation
Enable automatic key rotation for all customer-managed KMS keys.
...
EOF

# Re-initialize KB (force rebuild to include new doc)
python scripts/setup_knowledge_base.py --force
```

### 14.2 Add a PDF Security Standard

```bash
# Download CIS PDF
cp "CIS_Amazon_Web_Services_Foundations_Benchmark_v3.0.0.pdf" knowledge_base/sources/

# Re-initialize (PDF is automatically parsed by pypdf)
python scripts/setup_knowledge_base.py --force
```

### 14.3 Add Your Own Organization's Security Standards

```bash
# Place any .md, .txt, or .pdf files in knowledge_base/sources/
cp your_company_security_standards.pdf knowledge_base/sources/

# Or use the "user input" directory for documents you don't want to commit
mkdir -p "knowledge_base/user input"
cp sensitive_internal_policy.pdf "knowledge_base/user input/"

# Rebuild
python scripts/setup_knowledge_base.py --force
```

Documents in `knowledge_base/user input/` are loaded automatically by `KnowledgeBaseManager.load_all_sources()` but that path is gitignored by convention.

---

## 15. Terraform Support

Requires `python-hcl2` (already in `requirements.txt`):

```bash
pip install python-hcl2
```

### 15.1 Example Vulnerable Terraform (`my_s3.tf`)

```hcl
# VULNERABILITIES:
# 1. No aws_s3_bucket_public_access_block  → CRITICAL
# 2. No server_side_encryption_configuration → HIGH
# 3. acl = "public-read"                   → CRITICAL

resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-insecure-terraform-bucket"
  acl    = "public-read"   # CRITICAL: public read ACL
}

resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Open security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # CRITICAL: SSH open
  }
}
```

```bash
# Scan Terraform template
python scripts/run_scan.py my_s3.tf

# Output is identical format as CloudFormation scans
```

> **⚠ INTERRUPT — Complex HCL not supported:**
> Files using Terraform `module` blocks, `for_each`, `count`, `dynamic`, or `${var.x}`
> interpolation will produce incomplete or failed parsing. See INT-11.

---

## 16. Quick Reference Card

### Local Mode — Minimal Steps

```bash
# 1. Install
pip install -r requirements.txt

# 2. Configure
cat > .env << 'EOF'
MODE=local
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
EOF

# 3. Start Ollama
ollama serve &
ollama pull llama3

# 4. Initialize KB
python scripts/setup_knowledge_base.py

# 5. Scan
python scripts/run_scan.py my_template.yaml

# 6. Read report
cat data/reports/generated/$(ls -t data/reports/generated/ | head -1)
```

### AWS Mode — Minimal Steps

```bash
# 1. Install
pip install -r requirements.txt

# 2. Configure
cat > .env << 'EOF'
MODE=aws
AWS_REGION=us-east-1
AWS_PROFILE=your-profile
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
BEDROCK_EMBED_MODEL_ID=amazon.titan-embed-text-v2:0
PINECONE_API_KEY=pcsk_xxxxxxxxxxxx
PINECONE_INDEX=iac-security-kb
S3_REPORTS_BUCKET=your-reports-bucket
EOF

# 3. Verify AWS access
aws sts get-caller-identity --profile your-profile

# 4. Initialize KB (creates Pinecone index + uploads vectors)
python scripts/setup_knowledge_base.py

# 5. Scan
python scripts/run_scan.py my_template.yaml

# 6. Report is also uploaded to S3
aws s3 ls s3://your-reports-bucket/reports/
```

### Run All Tests

```bash
# All 23 tests (unit + integration)
python -m pytest tests/unit/ tests/integration/ -v

# Unit tests only (no external services needed)
python -m pytest tests/unit/ -v

# With coverage
python -m pytest tests/unit/ --cov=. --cov-report=term-missing
```

---

*Generated: 2026-04-05 | Scanner version: 1.0.0 | All 17 audit items resolved | 23/23 tests passing*

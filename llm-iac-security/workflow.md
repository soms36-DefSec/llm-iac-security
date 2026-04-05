# Project Workflow

This document explains how the LLM IaC Security Scanner works — from giving it an infrastructure file to getting a security report back.

---

## The Big Picture

You hand the scanner an infrastructure file (AWS CloudFormation or Terraform).
It reads the file, checks it against a security knowledge base, asks an AI to spot problems, and hands you a report.

```
Your IaC File
     |
     v
  [Parse]          Read and understand the file
     |
     v
  [Knowledge Base] Look up relevant security rules
     |
     v
  [AI Detection]   Ask the AI: "what's wrong here?"
     |
     v
  [Report]         Get a plain-English report with fixes
```

---

## Step-by-Step

### Step 0 — One-Time Setup

Before you run any scan, you need to fill the knowledge base once.
The scanner uses this as its "security rulebook."

```
python scripts/setup_knowledge_base.py
```

What it loads:
- S3 bucket security rules
- Security group best practices
- RDS database security rules
- Lambda function security rules
- CloudTrail monitoring guidelines

You only do this once. After that, the knowledge base stays on disk.

---

### Step 1 — You Provide an IaC File

You run:
```
python scripts/run_scan.py my_template.yaml --mode local
```

The file can be:
- CloudFormation YAML or JSON (`.yaml`, `.yml`, `.json`)
- Terraform HCL (`.tf`)

---

### Step 2 — Parse the File

The scanner reads your file and breaks it down into individual resources.

**Example input:**
```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-data-bucket
```

**What the scanner extracts:**
```
Resource: MyBucket
Type:     AWS::S3::Bucket
Properties:
  - BucketName: my-data-bucket
  - (no encryption configured)
  - (no versioning configured)
  - (no public access block)
```

Each resource becomes a structured entry the AI can reason about.

---

### Step 3 — Look Up the Knowledge Base (RAG)

The scanner converts the resource list into a search query and looks up the most relevant security rules from the knowledge base.

Think of it like a search engine for security best practices.

**Query:** "S3 bucket configuration"

**What comes back (snippets):**
```
- S3 buckets should have server-side encryption enabled (AES-256 or KMS)
- PublicAccessBlockConfiguration must set all four flags to true
- Versioning should be enabled to protect against accidental deletion
- Access logging should be enabled for audit trails
```

These snippets are passed to the AI alongside your template, so the AI has context when it looks for problems.

---

### Step 4 — AI Detects Vulnerabilities

The scanner sends both to the AI model:
1. Your template resources
2. The security snippets from the knowledge base

The AI responds with a structured list of findings.

**Example AI response (simplified):**
```
Finding 1:
  Resource:    MyBucket
  Problem:     No server-side encryption configured
  Severity:    HIGH
  Fix:         Add BucketEncryption with SSEAlgorithm: AES256

Finding 2:
  Resource:    MyBucket
  Problem:     Public access block not configured
  Severity:    HIGH
  Fix:         Add PublicAccessBlockConfiguration with all flags set to true
```

Duplicate findings (same resource + same problem) are automatically removed.

---

### Step 5 — Generate the Report

The scanner takes the findings and builds a Markdown report.

```
reports/scan_report_my_template_20260405_143022.md
```

**Report structure:**
```
# Security Scan Report: my_template

## Summary
- 2 HIGH findings
- 1 MEDIUM finding
- Scan time: 2026-04-05 14:30

## Findings

### [HIGH] MyBucket — No server-side encryption
What's wrong: ...
How to fix:   ...
Reference:    CIS AWS Benchmark 2.1.1

### [HIGH] MyBucket — Public access not blocked
...
```

---

## Two Modes

The scanner works in two modes depending on your environment.

### Local Mode (your laptop, no cloud needed)

```
MODE=local
```

| Component | What it uses |
|---|---|
| AI model | Ollama running llama3 locally |
| Knowledge base | ChromaDB stored on disk |
| Embeddings | HuggingFace all-MiniLM-L6-v2 |
| Report output | Local file |

Start Ollama before scanning:
```
ollama serve
ollama pull llama3
```

### AWS Mode (cloud, production-grade)

```
MODE=aws
```

| Component | What it uses |
|---|---|
| AI model | AWS Bedrock (Claude 3.5 Sonnet) |
| Knowledge base | Pinecone vector database |
| Embeddings | AWS Titan Text Embeddings V2 |
| Report output | S3 bucket + local file |

---

## What Happens Inside (One-Line Per Stage)

```
run_scan.py          →  reads your file, validates config
CloudFormationParser →  parses YAML/JSON into Python objects
TerraformParser      →  parses HCL into Python objects (for .tf files)
ResourceExtractor    →  turns parsed resources into readable text
RetrievalAgent       →  searches the KB, returns top-5 security snippets
VulnerabilityAgent   →  sends template + snippets to AI, gets findings back
ResponseParser       →  cleans up AI output, removes duplicates, adds severity
ReportAgent          →  formats findings into a Markdown report
S3Handler            →  uploads report to S3 (AWS mode only)
```

---

## CI/CD Gate (Optional)

If you use this in a deployment pipeline, you can block deployments when serious issues are found.

```
python cicd/pipeline_integration.py my_template.yaml --min-severity HIGH
```

- Exits with code `0` (pass) if no HIGH or CRITICAL findings
- Exits with code `1` (fail) if HIGH or CRITICAL findings are present
- INFO findings never block a pipeline

---

## Summary in One Sentence

> You give it an infrastructure file, it reads your security rulebook, asks an AI what's misconfigured, and hands you a prioritised report with fixes.

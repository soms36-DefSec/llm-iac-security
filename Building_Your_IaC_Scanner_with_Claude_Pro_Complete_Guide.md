# Complete Beginner's Workflow Guide: Building the LLM IaC Security Project with Claude Pro

> **Who is this for?** You have zero coding experience, a completed project vision (research paper + file structure), and access to Claude Pro. This guide walks you through every single step to turn that vision into a working software project.

---

## Table of Contents

1. [Understanding the Big Picture](#1-understanding-the-big-picture)
2. [Phase 1 — Setting Up Your Development Environment](#2-phase-1--setting-up-your-development-environment)
3. [Phase 2 — Preparing Claude Pro as Your Development Partner](#3-phase-2--preparing-claude-pro-as-your-development-partner)
4. [Phase 3 — Plugin and Tool Integration](#4-phase-3--plugin-and-tool-integration)
5. [Phase 4 — Development Workflow (Building the Project)](#5-phase-4--development-workflow-building-the-project)
6. [Phase 5 — System Integration](#6-phase-5--system-integration)
7. [Phase 6 — Testing and Quality Assurance](#7-phase-6--testing-and-quality-assurance)
8. [Phase 7 — Finalization and Deployment](#8-phase-7--finalization-and-deployment)
9. [Phase 8 — Documentation and Maintenance](#9-phase-8--documentation-and-maintenance)
10. [Appendix — Quick Reference Sheets](#10-appendix--quick-reference-sheets)

---

## 1. Understanding the Big Picture

### 1.1 What You Are Building

Your project is a **security scanning tool** that automatically checks cloud infrastructure files (called "CloudFormation templates") for security problems, then tells the developer exactly what is wrong and how to fix it. Think of it like a spell-checker, but instead of checking grammar, it checks whether your cloud setup has security holes.

The tool uses three "AI agents" (specialized mini-programs) working together in a pipeline:

- **Retrieval Agent ("The Librarian")** — Searches a knowledge base of security best practices to find relevant rules for the template being scanned.
- **Vulnerability Detection Agent ("The Detective")** — Uses an AI language model to read the template and the retrieved rules, then identifies security problems.
- **Report Generation Agent ("The Secretary")** — Takes the findings and writes a clear, readable security report.

### 1.2 Key Technical Terms Explained

| Term | What It Means (Simple Explanation) |
|---|---|
| **IaC (Infrastructure-as-Code)** | Writing your cloud server setup as a text file instead of clicking buttons in a web console. |
| **CloudFormation** | Amazon's specific format for writing IaC templates (usually YAML or JSON files). |
| **LLM (Large Language Model)** | An AI model (like Claude or Llama) that understands and generates human-like text. |
| **RAG (Retrieval-Augmented Generation)** | A technique where you first *search* a knowledge base for relevant info, then feed that info to the AI so its answers are more accurate. |
| **Vector Store / Vector Database** | A special database that stores text as numbers (called "embeddings") so you can search by meaning, not just exact words. |
| **Embeddings** | A way to turn text into a list of numbers that capture its meaning. Similar sentences produce similar numbers. |
| **API (Application Programming Interface)** | A way for one program to talk to another. Like a waiter taking your order to the kitchen. |
| **CI/CD** | Continuous Integration / Continuous Delivery — an automated system that tests and deploys code whenever changes are made. |
| **Repository (Repo)** | A folder that tracks all changes to your code using a tool called Git. |
| **Terminal / Command Line** | The text-based interface where you type commands to control your computer (no mouse clicking). |
| **Python** | The programming language your project is written in. |
| **pip** | Python's tool for installing additional code packages that other people have written. |
| **Virtual Environment (venv)** | An isolated Python workspace so your project's packages don't conflict with other projects. |
| **YAML / JSON** | Two common text formats for writing structured data. Your CloudFormation templates use these. |
| **Markdown (.md)** | A simple text formatting language used for documentation and reports. |

### 1.3 How the Development Journey Works

Building a software project is not a single leap — it is a series of small, testable steps. Here is how you will proceed:

```
Step 1: Set up tools on your computer
Step 2: Learn how to talk to Claude Pro effectively
Step 3: Build the project one module at a time (starting with the simplest parts)
Step 4: Connect the modules together
Step 5: Test everything
Step 6: Clean up and deploy
Step 7: Write documentation
```

Each step builds on the previous one. If something breaks, you only need to look at the most recent change.

---

## 2. Phase 1 — Setting Up Your Development Environment

### 2.1 What You Need Installed

Before writing any code, you need to install the right tools on your computer. Think of this like setting up a workshop before building furniture.

#### Operating System Requirements

This guide works on **Windows 10/11**, **macOS**, or **Linux (Ubuntu)**. Instructions are provided for all three where they differ.

#### Tool 1: Python (version 3.10 or higher)

Python is the programming language your project uses. Almost every file in your project is written in Python.

**How to check if Python is already installed:**
Open your terminal (see box below) and type:

```bash
python --version
```

If you see something like `Python 3.10.12`, you are good. If you see an error, you need to install it.

> **How to open the terminal:**
> - **Windows:** Press `Windows key`, type "PowerShell", and click on it.
> - **macOS:** Press `Cmd + Space`, type "Terminal", and press Enter.
> - **Linux:** Press `Ctrl + Alt + T`.

**How to install Python:**
Go to [python.org/downloads](https://python.org/downloads) and download the latest version (3.10 or above). During installation on Windows, **check the box that says "Add Python to PATH"** — this is critical.

#### Tool 2: Git (version control)

Git tracks every change you make to your code, like a detailed undo history. It also lets you back up your code online.

**Install Git:**
- **Windows:** Download from [git-scm.com](https://git-scm.com) and run the installer (accept all defaults).
- **macOS:** Type `git --version` in Terminal. If not installed, it will prompt you to install it.
- **Linux:** Run `sudo apt install git` in your terminal.

**Verify it works:**

```bash
git --version
```

#### Tool 3: A Code Editor (VS Code recommended)

A code editor is like a specialized word processor for writing code. It color-codes your code, helps catch typos, and makes file navigation easy.

**Install VS Code:**
Download from [code.visualstudio.com](https://code.visualstudio.com) and install it.

**Recommended VS Code extensions (install from the Extensions tab on the left sidebar):**
- **Python** (by Microsoft) — adds Python language support
- **Pylint** or **Flake8** — highlights code mistakes in real time
- **YAML** — helps you read CloudFormation templates
- **GitLens** — shows Git history inside the editor

#### Tool 4: An AWS Account (Free Tier is fine for development)

Your project interacts with AWS services (Amazon Bedrock, OpenSearch, S3). You can start development with mock/simulated versions, but you will eventually need a real AWS account.

**Sign up:** [aws.amazon.com/free](https://aws.amazon.com/free)

> **Cost note:** Amazon Bedrock (the AI service) charges per API call. During early development, you will use mock data so you don't incur costs. When you are ready to test with real AI, budget around $5–20 for experimentation.

### 2.2 Creating Your Project Folder and Virtual Environment

Now let's set up your workspace. Open your terminal and run these commands one at a time:

```bash
# Step 1: Navigate to where you want your project (e.g., your home folder)
cd ~

# Step 2: Create the project folder
mkdir llm-iac-security
cd llm-iac-security

# Step 3: Create a Python virtual environment
# (This isolates your project's packages from the rest of your computer)
python -m venv venv

# Step 4: Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# You should now see (venv) at the beginning of your terminal prompt
# This means the virtual environment is active
```

> **Important:** Every time you open a new terminal window to work on this project, you must activate the virtual environment again using the command from Step 4 above.

### 2.3 Validating Your Folder Structure

Your project already has a planned file structure (from the document you prepared). Let's create the skeleton now. Ask Claude Pro:

**Prompt to use in Claude Pro:**

```
I have the following planned folder structure for my Python project.
Please generate a bash script that creates all of these folders and
empty __init__.py files. Do NOT create the actual code files yet —
just the folder skeleton with empty placeholder files.

[Paste your entire file structure from project_file_structure.txt here]
```

Claude will give you a bash script. Copy it, paste it into your terminal, and run it. Then verify by running:

```bash
# On macOS/Linux:
find . -type d | head -40

# On Windows PowerShell:
Get-ChildItem -Recurse -Directory | Select-Object FullName | Select-First 40
```

This shows you the folder tree. Compare it to your planned structure to make sure everything matches.

### 2.4 Installing Initial Dependencies

Your project needs external Python packages. Create a file called `requirements.txt` in your project root folder and ask Claude Pro to help:

**Prompt:**

```
Based on my project structure (a multi-agent LLM system that scans
CloudFormation templates using RAG, vector search, and Amazon Bedrock),
generate a requirements.txt file listing all the Python packages I'll need.
Include version numbers. Organize them with comments explaining what
each package is for. Include packages for: YAML parsing, AWS SDK (boto3),
vector search (opensearch or faiss), text embeddings, testing (pytest),
markdown generation, and any other utilities the project needs.
```

Once Claude gives you the file, save it as `requirements.txt`, then install everything:

```bash
pip install -r requirements.txt
```

If you see errors, copy the entire error message and paste it to Claude Pro with the prompt: "I got this error when installing my Python requirements. How do I fix it?"

### 2.5 Setting Up Git Version Control

Initialize Git so every change is tracked:

```bash
# Inside your project folder (llm-iac-security/)
git init

# Create a .gitignore file (tells Git which files to ignore)
# Ask Claude Pro to generate this for you:
```

**Prompt:**

```
Generate a .gitignore file for a Python project that uses virtual
environments, has .env files with secrets, and generates reports.
Include common patterns for Python, VS Code, macOS, and AWS credentials.
```

Save Claude's output as `.gitignore`, then make your first commit:

```bash
git add .
git commit -m "Initial project skeleton with folder structure"
```

> **What is a commit?** Think of it as saving a snapshot of your entire project. You can always go back to any snapshot if something goes wrong.

### 2.6 Setting Up Environment Variables

Your project will need secret values like AWS keys. These should **never** be saved in your code files. Instead, they go in a special file called `.env`.

Create a file called `.env.example` (this is a template you can share) and `.env` (this is your real secrets file, which Git will ignore):

```bash
# .env.example (safe to share — no real values)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key-here
AWS_SECRET_ACCESS_KEY=your-secret-here
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
OPENSEARCH_ENDPOINT=https://your-opensearch-domain.us-east-1.es.amazonaws.com
```

Copy `.env.example` to `.env` and fill in your real values later when you have them.

---

## 3. Phase 2 — Preparing Claude Pro as Your Development Partner

### 3.1 How Claude Pro Fits Into Your Workflow

Claude Pro is your coding partner. You will use it to generate code, explain concepts, debug errors, review code quality, and write tests. However, Claude works best when you give it clear, structured instructions.

**Golden rule:** The better your prompt, the better the code Claude writes.

### 3.2 Setting Up a Project Context File

Claude does not remember previous conversations (unless you use Projects). To avoid repeating yourself, create a **project context file** that you paste at the beginning of important conversations.

Create a file called `CLAUDE_CONTEXT.md`:

```markdown
# Project Context for Claude Pro

## Project Name
LLM Agentic Workflow for Automated Vulnerability Detection
and Remediation in Infrastructure-as-Code

## Tech Stack
- Language: Python 3.10+
- AI Model: Anthropic Claude Sonnet 3.5 V2 (via Amazon Bedrock)
  OR local Ollama with Llama 3 (for offline development)
- Embeddings: Titan Text Embeddings V2 (or HuggingFace all-MiniLM for local)
- Vector Store: Amazon OpenSearch (or ChromaDB/FAISS for local)
- IaC Format: AWS CloudFormation (YAML/JSON)
- Testing: pytest
- CI/CD: GitHub Actions

## Architecture
Three agents in a pipeline:
1. Retrieval Agent — searches knowledge base for relevant security rules
2. Vulnerability Detection Agent — uses LLM to find misconfigurations
3. Report Generation Agent — formats findings as Markdown report

## Key Constraints
- I am a beginner with no coding experience
- Please explain every code block with inline comments
- Use simple, readable code over clever/compact code
- Always include error handling
- Follow Python best practices (PEP 8 style)

## Current File Structure
[Paste your file structure here]
```

### 3.3 How to Write Effective Prompts for Claude Pro

Here are prompt patterns that work well for each type of task:

#### Pattern 1: Generating a New Code File

```
I am building [module name] for my project. Here is the context:
[paste relevant section of CLAUDE_CONTEXT.md]

This file should:
- [requirement 1]
- [requirement 2]
- [requirement 3]

The file is located at: [path from your file structure]

It depends on / imports from: [list any other modules it needs]

Please write the complete Python file with:
- Detailed inline comments explaining every section
- Docstrings for every function and class
- Type hints on all function parameters
- Error handling with try/except blocks
- A simple example at the bottom in an if __name__ == "__main__": block
```

#### Pattern 2: Debugging an Error

```
I got the following error when running [file name]:

[Paste the COMPLETE error message — everything in red or after "Traceback"]

Here is the relevant code:
[Paste the code file, or at least the function where the error occurs]

Please:
1. Explain what this error means in simple language
2. Show me exactly which line is causing the problem
3. Give me the corrected code
4. Explain what you changed and why
```

#### Pattern 3: Understanding Code

```
Please explain this code to me like I am a complete beginner.
Go line by line and explain what each line does and why it is there.
Use analogies where helpful.

[Paste the code]
```

#### Pattern 4: Reviewing Code Quality

```
Please review this code for:
1. Bugs or logic errors
2. Security issues
3. Missing error handling
4. Code style issues (PEP 8)
5. Anything a senior developer would change

[Paste the code]

Give me the improved version with comments explaining each change.
```

#### Pattern 5: Writing Tests

```
Please write pytest test cases for the following code.
Include tests for:
- Normal/expected inputs (happy path)
- Edge cases (empty input, very large input, None values)
- Error cases (invalid input, missing files)

[Paste the code to test]

The test file should be at: tests/unit/test_[module_name].py
Use pytest fixtures where appropriate. Explain each test case.
```

### 3.4 Managing Conversations with Claude Pro

- **One module per conversation.** Start a new conversation for each major module (e.g., one for the parser, one for the retrieval agent). This keeps context focused.
- **Use Claude's Projects feature.** If available, create a Project and upload your `CLAUDE_CONTEXT.md`, file structure, and research paper. This way, Claude remembers your project context across conversations within that Project.
- **Save important outputs.** When Claude generates code, immediately copy it into the correct file in VS Code. Do not rely on finding it later in chat history.
- **Iterate, do not rewrite from scratch.** If Claude's first attempt is 80% right, paste the code back and say "This is mostly correct but [specific issue]. Please fix just that part."

---

## 4. Phase 3 — Plugin and Tool Integration

### 4.1 AWS CLI Setup

The AWS CLI (Command Line Interface) lets you interact with AWS services from your terminal.

**Install:**
- **Windows:** Download from [aws.amazon.com/cli](https://aws.amazon.com/cli)
- **macOS:** `brew install awscli` (if you have Homebrew) or download the installer
- **Linux:** `sudo apt install awscli`

**Configure:**

```bash
aws configure
```

It will ask for four things:

```
AWS Access Key ID: [your key from AWS console → IAM → Security Credentials]
AWS Secret Access Key: [your secret key]
Default region name: us-east-1
Default output format: json
```

**Test the connection:**

```bash
aws sts get-caller-identity
```

If you see your account ID, it works. If you get an error, paste the error into Claude Pro for help.

### 4.2 Amazon Bedrock Setup

Amazon Bedrock is the AWS service that gives you access to AI models (including Claude Sonnet).

**Step 1:** Go to the AWS Console → search for "Bedrock" → click on it.

**Step 2:** In the left sidebar, click "Model access" → click "Manage model access".

**Step 3:** Check the box next to "Anthropic Claude 3.5 Sonnet v2" and "Amazon Titan Text Embeddings V2". Click "Save changes". Access may take a few minutes to be granted.

**Step 4:** Test it from your terminal:

```bash
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-5-sonnet-20241022-v2:0 \
  --content-type application/json \
  --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":100,"messages":[{"role":"user","content":"Say hello"}]}' \
  output.json

cat output.json
```

If you see a response from Claude, Bedrock is working.

### 4.3 Local Development Alternative (Ollama + ChromaDB)

If you want to develop **without AWS costs**, you can run everything locally using free, open-source tools. This is the approach shown in your system architecture diagram.

#### Install Ollama (Local LLM Server)

Ollama lets you run AI models on your own computer.

**Install:**
- Go to [ollama.com](https://ollama.com) and download for your OS
- Open your terminal and run:

```bash
ollama pull llama3
ollama serve
```

This downloads the Llama 3 model and starts a local AI server.

**Test it:**

```bash
curl http://localhost:11434/api/generate -d '{"model":"llama3","prompt":"Hello"}'
```

#### Install ChromaDB (Local Vector Store)

```bash
pip install chromadb
```

ChromaDB runs entirely in Python — no separate server needed for basic usage.

#### Install HuggingFace Embeddings (Local Embedding Model)

```bash
pip install sentence-transformers
```

This gives you the `all-MiniLM-L6-v2` model for converting text into embeddings locally.

### 4.4 Setting Up Your Configuration Files

Your project has a `config/` folder for settings. Ask Claude Pro to generate these:

**Prompt:**

```
I need a config/settings.py file for my project that:
- Loads values from a .env file using python-dotenv
- Has two modes: "local" (using Ollama + ChromaDB) and "aws" (using Bedrock + OpenSearch)
- Stores all configurable values as constants (model names, endpoints, thresholds)
- Includes clear comments explaining each setting
- Has a function to switch between local and AWS mode

Also generate config/bedrock_config.py that wraps the AWS Bedrock client setup,
and config/logging_config.py that sets up Python logging to both console and a log file.

I am a beginner — please explain everything with comments.
```

### 4.5 Testing Your Tool Integration

After setting up each tool, run a quick test to confirm it works. Create a file called `scripts/test_setup.py`:

**Prompt:**

```
Write a Python script called test_setup.py that checks whether all my
project dependencies are correctly installed and configured. It should:

1. Check Python version is 3.10+
2. Try importing all required packages (boto3, yaml, chromadb, etc.)
3. Check if .env file exists and has required variables
4. Try connecting to the local Ollama server (if in local mode)
5. Try connecting to AWS Bedrock (if in AWS mode)
6. Print a clear PASS/FAIL status for each check

Use green text for PASS and red text for FAIL if possible.
```

Run it with:

```bash
python scripts/test_setup.py
```

Fix any failures before moving on. For each failure, paste the error into Claude Pro and ask for help.

### 4.6 Troubleshooting Common Setup Issues

| Problem | Likely Cause | How to Fix |
|---|---|---|
| `python: command not found` | Python not in PATH | Reinstall Python with "Add to PATH" checked |
| `pip: command not found` | pip not installed | Run `python -m ensurepip --upgrade` |
| `ModuleNotFoundError: No module named 'xyz'` | Package not installed in your virtual environment | Make sure venv is activated, then run `pip install xyz` |
| `AWS credentials not found` | AWS CLI not configured | Run `aws configure` and enter your keys |
| `Connection refused` (Ollama) | Ollama server not running | Run `ollama serve` in a separate terminal |
| `Permission denied` | Insufficient file permissions | On Mac/Linux: add `sudo` before the command |

---

## 5. Phase 4 — Development Workflow (Building the Project)

### 5.1 Breaking the Project into Phases

Never try to build everything at once. Here is the recommended build order, starting with the simplest pieces and building up:

```
Sprint 1 (Foundation):     config/, utils/, parsers/
Sprint 2 (Knowledge Base): knowledge_base/, llm/
Sprint 3 (Agents):         agents/, orchestrator/
Sprint 4 (Reporting):      reporting/
Sprint 5 (CI/CD):          cicd/, scripts/
Sprint 6 (Polish):         storage/, tests/, documentation
```

Each sprint should take roughly 1–2 weeks (at a learning pace). Complete one sprint before starting the next.

### 5.2 Sprint 1 — Foundation Layer

This sprint builds the utility code that everything else depends on.

#### Step 1: Build `utils/exceptions.py`

This file defines custom error types for your project.

**Prompt for Claude Pro:**

```
Write utils/exceptions.py for my IaC security scanning project.
Create custom exception classes for:
- TemplateParsingError (when a CloudFormation file can't be read)
- LLMConnectionError (when the AI model can't be reached)
- KnowledgeBaseError (when the vector store has issues)
- ReportGenerationError (when report creation fails)
- ConfigurationError (when settings are missing or invalid)

Each should inherit from a base IaCSecurityError class.
Include docstrings explaining when each exception is used.
I am a complete beginner — please add comments explaining Python
class inheritance and exception handling.
```

#### Step 2: Build `utils/file_utils.py`

**Prompt:**

```
Write utils/file_utils.py with helper functions for:
- Reading a YAML file and returning its contents as a Python dictionary
- Reading a JSON file and returning its contents as a Python dictionary
- Writing text to a file (for saving reports)
- Checking if a file exists and is readable
- Listing all .yaml and .json files in a given directory

Use pathlib (not os.path) for file operations.
Include error handling that raises my custom exceptions from utils/exceptions.py.
Add inline comments explaining everything.
```

#### Step 3: Build `parsers/cloudformation_parser.py`

This is the module that reads CloudFormation templates and extracts useful information.

**Prompt:**

```
Write parsers/cloudformation_parser.py for my project.

It should:
1. Accept a file path to a CloudFormation template (YAML or JSON)
2. Parse the file into a Python data structure
3. Extract all "Resources" defined in the template
4. For each resource, identify:
   - The resource logical name (its key in the Resources section)
   - The resource Type (e.g., AWS::S3::Bucket, AWS::IAM::Role)
   - All Properties defined for that resource
5. Return a structured summary as a Python dictionary

Also create parsers/resource_extractor.py that has specialized
extraction logic for these AWS resource types:
- S3 buckets (check for encryption, public access, versioning settings)
- IAM roles and policies (check for overly permissive actions like *)
- Security Groups (check for unrestricted ingress rules like 0.0.0.0/0)
- RDS instances (check for encryption, public accessibility)

Include a parsers/base_parser.py abstract base class that defines the
interface all parsers must follow.

I am a beginner. Please explain concepts like abstract classes, YAML
parsing, and dictionary traversal in the comments.
```

#### Step 4: Test What You Have Built So Far

Create a simple test CloudFormation template to test your parser:

**Prompt:**

```
Create a sample CloudFormation template file (YAML format) called
tests/fixtures/templates/T1_basic_s3.yaml that defines:
- An S3 bucket WITHOUT encryption (this is a vulnerability)
- An S3 bucket WITH public access enabled (this is a vulnerability)

Then write a quick test script I can run to verify my parser works:
- Load the template
- Parse it
- Print the extracted resources
- Print any security-relevant properties found

I want to see output in my terminal confirming the parser correctly
identified the resources and their properties.
```

Run the test:

```bash
python -m pytest tests/unit/test_cloudformation_parser.py -v
```

> **What does `-v` mean?** It stands for "verbose" — it shows you the name and result of each individual test instead of just a summary.

### 5.3 Sprint 2 — Knowledge Base Layer

Now you build the RAG (Retrieval-Augmented Generation) system.

#### Step 1: Create Knowledge Base Source Documents

**Prompt:**

```
For my IaC security project's knowledge base, create the following
Markdown files containing AWS security best practices:

1. knowledge_base/sources/aws_well_architected.md
   - Key security principles from the AWS Well-Architected Framework
   - Focus on: encryption, least privilege, network security

2. knowledge_base/sources/cis_benchmarks.md
   - CIS Benchmark guidelines relevant to CloudFormation resources
   - Focus on: S3, IAM, Security Groups, RDS

3. knowledge_base/sources/aws_secrets_manager.md
   - Best practices for managing secrets in AWS

4. knowledge_base/sources/iam_best_practices.md
   - IAM least-privilege guidelines
   - Common overly-permissive patterns to avoid

Keep each file focused and concise (under 200 lines).
Format them with clear headings so they chunk well for RAG retrieval.
```

#### Step 2: Build the Embeddings and Vector Store

**Prompt:**

```
Write these files for my knowledge base system:

1. knowledge_base/embeddings.py
   - A wrapper class that can use EITHER HuggingFace all-MiniLM (local mode)
     OR Amazon Titan Text Embeddings V2 (AWS mode)
   - Method: embed_text(text) → returns a list of numbers (the embedding)
   - Method: embed_batch(texts) → returns embeddings for multiple texts

2. knowledge_base/vector_store.py
   - A wrapper class that can use EITHER ChromaDB (local mode)
     OR Amazon OpenSearch (AWS mode)
   - Method: add_documents(texts, metadata) → stores documents with their embeddings
   - Method: search(query, top_k=5) → finds the most relevant documents
   - Method: clear() → removes all documents (useful for resetting)

3. knowledge_base/kb_manager.py
   - Manages the full lifecycle of the knowledge base
   - Method: initialize() → loads all source documents, chunks them, embeds them, stores them
   - Method: query(question) → searches for relevant knowledge base entries
   - "Chunking" means splitting long documents into smaller overlapping pieces

Use the config/settings.py to determine which mode (local vs AWS) to use.
Explain chunking, embeddings, and vector search in the comments for a beginner.
```

#### Step 3: Build the LLM Client

**Prompt:**

```
Write these files for the LLM integration layer:

1. llm/bedrock_client.py
   - A client class that can talk to EITHER Ollama (local) OR Amazon Bedrock (AWS)
   - Method: generate(prompt, system_message=None) → returns the AI's text response
   - Include retry logic (try 3 times if the API call fails)
   - Include timeout handling

2. llm/prompt_templates.py
   - Store all prompt templates as multi-line strings
   - VULNERABILITY_DETECTION_SYSTEM_PROMPT: tells the AI it is a cloud security expert
   - VULNERABILITY_DETECTION_USER_PROMPT: template with placeholders for
     {template_summary} and {best_practices}
   - REPORT_GENERATION_PROMPT: template for creating the final report

3. llm/prompt_builder.py
   - Takes a parsed CloudFormation template and retrieved knowledge base snippets
   - Fills in the prompt templates with actual data
   - Returns the complete prompt ready to send to the LLM

4. llm/response_parser.py
   - Parses the LLM's text response into a structured Python dictionary
   - Extracts: vulnerability name, affected resource, severity, description, remediation
   - Handles cases where the LLM response is malformed or unexpected

Please add extensive comments explaining prompt engineering concepts.
```

### 5.4 Sprint 3 — Building the AI Agents

This is the core of your project. Each agent is a class that performs one specialized task.

#### Step 1: Base Agent

**Prompt:**

```
Write agents/base_agent.py — an abstract base class that all agents inherit from.
It should define:
- An __init__ method that accepts a config object
- An abstract method: run(input_data) → returns output_data
- A logging setup so every agent logs what it is doing
- A method to measure how long the agent takes to run

Explain abstract classes and inheritance in the comments.
```

#### Step 2: Retrieval Agent

**Prompt:**

```
Write agents/retrieval_agent.py.
This agent ("The Librarian"):
1. Receives a parsed CloudFormation template summary
2. Extracts the key resource types mentioned (S3, IAM, etc.)
3. Queries the knowledge base vector store for relevant best practices
4. Returns the top 5 most relevant knowledge base snippets

It should inherit from base_agent.py and implement the run() method.
Include logging at each step so I can see what the agent is doing.
```

#### Step 3: Vulnerability Detection Agent

**Prompt:**

```
Write agents/vulnerability_detection_agent.py.
This agent ("The Detective"):
1. Receives the CloudFormation template AND the retrieved best-practice snippets
2. Builds a prompt using the prompt_builder
3. Sends the prompt to the LLM
4. Parses the LLM's response to extract structured vulnerability findings
5. Returns a list of vulnerability dictionaries, each containing:
   - resource_name, resource_type, vulnerability_type, severity,
     description, remediation, best_practice_reference

It should inherit from base_agent.py.
Handle the case where the LLM returns no vulnerabilities (clean template).
Handle the case where the LLM response cannot be parsed.
```

#### Step 4: Report Generation Agent

**Prompt:**

```
Write agents/report_generation_agent.py.
This agent ("The Secretary"):
1. Receives the list of vulnerability findings
2. Classifies each finding by severity (CRITICAL, HIGH, MEDIUM, LOW)
3. Generates a Markdown report using the report template
4. The report includes:
   - Executive summary with total counts by severity
   - Detailed findings table
   - Remediation steps for each finding
   - References to the best practices that were violated
5. Returns the report as a string (Markdown formatted)

Also write reporting/severity_classifier.py that assigns severity
based on the type of vulnerability found.
Also write reporting/markdown_formatter.py with helper functions
for creating Markdown tables, headers, and code blocks.
```

#### Step 5: Build the Orchestrator

**Prompt:**

```
Write orchestrator/pipeline.py — the main pipeline that ties everything together.
It should:
1. Accept a file path to a CloudFormation template
2. Parse the template using the cloudformation_parser
3. Run the Retrieval Agent to get relevant best practices
4. Run the Vulnerability Detection Agent to find issues
5. Run the Report Generation Agent to create the report
6. Save the report to the data/reports/generated/ folder
7. Return the report and a summary

Also write orchestrator/workflow_manager.py that manages the state
passing between agents and handles errors at any stage.

Include detailed logging so I can follow the entire pipeline execution.
```

### 5.5 How to Handle Code That Claude Pro Generates

When Claude gives you code, follow this checklist every time:

1. **Read the code** — Even if you do not understand every line, read through it. Look for the comments Claude added.
2. **Ask questions** — If anything is unclear, say "Explain lines 15-30 of this code in simple terms."
3. **Save it to the correct file** — Copy the code into the right file in VS Code.
4. **Run it** — Try to execute the code or its tests immediately.
5. **Fix errors** — If it fails, paste the error back to Claude.
6. **Commit to Git** — Once it works, save a snapshot:

```bash
git add .
git commit -m "Add [module name] - [brief description of what it does]"
```

### 5.6 Debugging Workflow

When you encounter an error (and you will — this is completely normal), follow this process:

```
1. READ the error message carefully (especially the last few lines)
2. IDENTIFY which file and line number is mentioned
3. LOOK at that line in your code
4. PASTE the full error + relevant code into Claude Pro
5. APPLY Claude's fix
6. RE-RUN the code
7. REPEAT if needed (some bugs reveal other bugs underneath)
```

**Common Python errors you will encounter:**

| Error | What It Means | Typical Fix |
|---|---|---|
| `IndentationError` | Your code spacing is wrong (Python is strict about this) | Make sure all indentation uses 4 spaces (not tabs) |
| `NameError: name 'x' is not defined` | You used a variable before creating it | Check for typos in variable names |
| `ImportError: No module named 'x'` | A package is not installed | Run `pip install x` |
| `TypeError: expected str, got int` | You passed the wrong type of data | Check what type the function expects |
| `KeyError: 'x'` | You tried to access a dictionary key that does not exist | Use `.get('x', default_value)` instead |
| `FileNotFoundError` | The file path is wrong | Double-check the path; use absolute paths for debugging |

---

## 6. Phase 5 — System Integration

### 6.1 Connecting All the Pieces

At this point you have individual modules. Now you connect them into a working system.

**Prompt for Claude Pro:**

```
I have built all the individual modules for my project. Now I need to
create the main entry point script: scripts/run_scan.py

This script should:
1. Accept a command-line argument for the CloudFormation template file path
2. Accept an optional --mode flag ("local" or "aws", default "local")
3. Accept an optional --output flag for where to save the report
4. Initialize the configuration based on mode
5. Initialize the knowledge base (or use cached version)
6. Run the full pipeline (parse → retrieve → detect → report)
7. Print a summary to the terminal
8. Save the full report to the output path

Include argument parsing using argparse.
Include a progress indicator so I can see what stage the tool is at.
Add error handling that gives friendly error messages if something goes wrong.

Example usage:
  python scripts/run_scan.py templates/my_template.yaml --mode local --output report.md
```

### 6.2 End-to-End Integration Test

Run the full system on a test template:

```bash
# Make sure your virtual environment is activated
# Make sure Ollama is running (if using local mode): ollama serve

# Run a scan on a test template
python scripts/run_scan.py tests/fixtures/templates/T1_basic_s3.yaml --mode local
```

If this works and produces a report, congratulations — your core system is functional.

If it fails, note exactly where it fails (which agent, which step) and use the debugging workflow from section 5.6.

### 6.3 API Layer (Optional)

If you want other programs to use your tool (not just the command line), you can add a simple web API:

**Prompt:**

```
Create a simple Flask or FastAPI web server that exposes my IaC scanning
tool as a REST API. Endpoints:
- POST /scan — accepts a CloudFormation template (YAML text) in the request body,
  runs the full pipeline, and returns the report as JSON
- GET /health — returns a simple status check

This is optional and for future use. Keep it simple.
```

---

## 7. Phase 6 — Testing and Quality Assurance

### 7.1 Why Testing Matters

Testing means writing small programs that automatically check if your code works correctly. When you change something later, you can run all tests to make sure you did not break anything. This is essential for code quality.

### 7.2 Setting Up the Test Framework

Your project uses **pytest** (a Python testing tool). It is already in your requirements.txt.

Create the test configuration file:

**Prompt:**

```
Write tests/conftest.py — the shared test configuration for my project.
Include pytest fixtures for:
- A sample CloudFormation template (loaded from fixtures)
- A mock LLM client (returns pre-written responses so tests don't need real AI)
- A mock vector store (returns pre-written knowledge base results)
- A temporary directory for test report output
- Ground truth annotations (loaded from fixtures/ground_truth/annotations.json)

Explain what pytest fixtures are and how they work in the comments.
```

### 7.3 Writing Unit Tests for Each Module

For each module you built, ask Claude Pro to write tests:

**Prompt template (repeat for each module):**

```
Write comprehensive unit tests for [module file path].
The test file should be at: tests/unit/test_[module_name].py

Include tests for:
- All public methods
- Normal expected behavior (happy path)
- Edge cases (empty input, None, very large input)
- Error handling (what happens when something goes wrong)
- Boundary conditions

Use the mock fixtures from conftest.py so tests don't need real
AWS services or real LLM calls.

Expected module files to test:
- test_cloudformation_parser.py
- test_retrieval_agent.py
- test_vulnerability_agent.py
- test_report_generation_agent.py
- test_prompt_builder.py
- test_severity_classifier.py
```

### 7.4 Running Tests

```bash
# Run ALL tests
python -m pytest tests/ -v

# Run only unit tests
python -m pytest tests/unit/ -v

# Run a single test file
python -m pytest tests/unit/test_cloudformation_parser.py -v

# Run tests and show how much code is covered
python -m pytest tests/ -v --cov=. --cov-report=term-missing
```

> **Code coverage** tells you what percentage of your code is actually being tested. Aim for at least 70%.

### 7.5 Integration Testing

Integration tests check that modules work together correctly.

**Prompt:**

```
Write tests/integration/test_pipeline_end_to_end.py that:
1. Loads a test CloudFormation template with known vulnerabilities
2. Runs the FULL pipeline (using mock LLM responses, not real AI)
3. Checks that the output report contains the expected vulnerabilities
4. Checks that no false vulnerabilities are reported for a clean template

Also write tests/integration/test_rag_integration.py that:
1. Initializes the knowledge base with test documents
2. Queries it with a sample question
3. Verifies the returned results are relevant
```

### 7.6 Evaluation Metrics Script

Your research paper measures precision, recall, and F1 score. Build the evaluation script:

**Prompt:**

```
Write scripts/evaluate_results.py that:
1. Loads the ground truth annotations from tests/fixtures/ground_truth/annotations.json
2. Runs the scanning tool on all 10 test templates (T1 through T10)
3. Compares the detected vulnerabilities against ground truth
4. Calculates per-template and overall:
   - Precision (of the things flagged, how many were real issues?)
   - Recall (of the real issues, how many were flagged?)
   - F1 Score (harmonic mean of precision and recall)
5. Prints a formatted table matching Table 1 from the research paper
6. Saves the results to a JSON file

Explain precision, recall, and F1 in the comments for a beginner.
```

### 7.7 Manual Testing Checklist

In addition to automated tests, manually verify these scenarios:

```
□ Scan a template with known S3 bucket vulnerabilities → report lists them
□ Scan a template with IAM overly-permissive roles → report lists them
□ Scan a template with open Security Group rules → report lists them
□ Scan a template with no vulnerabilities → report says "no issues found"
□ Scan an invalid YAML file → friendly error message (not a crash)
□ Scan a non-existent file → friendly error message
□ Run with --mode local → uses Ollama + ChromaDB
□ Run with --mode aws → uses Bedrock + OpenSearch (if configured)
□ Report is saved to the correct output path
□ Report Markdown renders correctly (open it in VS Code preview: Ctrl+Shift+V)
```

---

## 8. Phase 7 — Finalization and Deployment

### 8.1 Code Cleanup

Before sharing your project, clean it up:

**Prompt:**

```
Review my entire project and help me clean up:
1. Remove any debug print() statements (replace with proper logging)
2. Ensure all functions have docstrings
3. Ensure all files have a module-level docstring at the top
4. Check that .env is in .gitignore (secrets must never be committed)
5. Check for any hardcoded values that should be in config/settings.py
6. Ensure consistent coding style throughout

Also run:
  python -m flake8 . --max-line-length=100 --exclude=venv

And fix any warnings.
```

### 8.2 Creating setup.py

This file makes your project installable as a Python package:

**Prompt:**

```
Write a setup.py file for my project that:
- Lists all dependencies from requirements.txt
- Defines a console entry point so users can run: iac-scan my_template.yaml
- Includes metadata (name, version, author, description)

Also write a Makefile with common commands:
- make install (installs the project)
- make test (runs all tests)
- make lint (runs code style checks)
- make scan TEMPLATE=path (runs a scan)
- make clean (removes generated files)
```

### 8.3 Hosting and Deployment

Your tool is primarily a command-line tool, so "deployment" means making it easy for others to install and use.

#### Option A: GitHub Repository (Recommended)

1. Create a free account at [github.com](https://github.com)
2. Create a new repository (click the "+" button → "New repository")
3. Name it `llm-iac-security` and keep it public (or private if preferred)
4. Follow GitHub's instructions to push your local code:

```bash
git remote add origin https://github.com/YOUR_USERNAME/llm-iac-security.git
git branch -M main
git push -u origin main
```

#### Option B: CI/CD Pipeline (GitHub Actions)

Your project includes a GitHub Actions workflow file. Ask Claude Pro to finalize it:

**Prompt:**

```
Write cicd/github_actions/iac_security_scan.yml — a GitHub Actions
workflow that:
1. Triggers on every push and pull request to the main branch
2. Sets up Python 3.10
3. Installs dependencies from requirements.txt
4. Runs all unit tests with pytest
5. Runs the flake8 linter
6. (Optional) runs a sample scan on a test template

This should work without AWS credentials (use mock mode).
Include comments explaining every section for a beginner.
```

Copy this file to `.github/workflows/iac_security_scan.yml` in your project root (note the `.github` folder with the dot at the beginning).

### 8.4 Environment Variables for Deployment

Create clear documentation about what environment variables are needed:

```
Required Environment Variables:
  MODE=local|aws                          (which infrastructure to use)

For AWS mode only:
  AWS_REGION=us-east-1                    (your AWS region)
  AWS_ACCESS_KEY_ID=AKIA...               (your AWS access key)
  AWS_SECRET_ACCESS_KEY=...               (your AWS secret key)
  BEDROCK_MODEL_ID=anthropic.claude-...   (the Bedrock model identifier)
  OPENSEARCH_ENDPOINT=https://...         (your OpenSearch domain URL)

For local mode only:
  OLLAMA_HOST=http://localhost:11434      (where Ollama is running)
  OLLAMA_MODEL=llama3                     (which model to use)
```

### 8.5 Deployment Verification

After pushing to GitHub and setting up CI/CD, verify:

```
□ GitHub Actions workflow runs and passes (green checkmark)
□ Another person can clone the repo and follow the README to get it running
□ All tests pass on a fresh install
□ The .env file is NOT in the repository (check with: git log --all -- .env)
```

---

## 9. Phase 8 — Documentation and Maintenance

### 9.1 Writing the README.md

Your README is the first thing anyone sees when they visit your project. It needs to be comprehensive and welcoming.

**Prompt:**

```
Write a professional README.md for my project. Include:

1. Project title and a one-paragraph description
2. A badges section (Python version, license, build status)
3. Table of contents
4. Features list
5. Architecture diagram (use a Mermaid diagram showing the three agents)
6. Prerequisites (what you need installed)
7. Installation instructions (step by step, with code blocks)
8. Quick start guide (how to run your first scan in 3 commands)
9. Configuration section (environment variables, local vs AWS mode)
10. Usage examples (common commands with expected output)
11. Project structure (the folder tree with one-line descriptions)
12. How to run tests
13. Contributing guidelines (how others can help improve the project)
14. License (MIT is a good default)
15. Acknowledgments (cite the research paper and any tools used)

Make it visually appealing with proper Markdown formatting.
The tone should be professional but approachable.
```

### 9.2 Additional Documentation Files

**Prompt:**

```
Write these documentation files for my project:

1. docs/setup_guide.md — Detailed environment setup for all 3 operating systems
2. docs/architecture.md — System design explanation with diagrams
3. docs/agent_descriptions.md — What each agent does, its inputs and outputs
4. docs/api_reference.md — All public functions/classes with usage examples

Also create a CHANGELOG.md that documents version 1.0.0 features.
```

### 9.3 Maintaining the Project

After your project is complete, you will need to maintain it over time:

- **Update dependencies** periodically — Run `pip list --outdated` to see which packages have new versions.
- **Update the knowledge base** — When AWS releases new security recommendations, add them to your `knowledge_base/sources/` folder and re-run the initialization script.
- **Monitor GitHub Issues** — If you make the repo public, people may report bugs or suggest features.
- **Review and merge Pull Requests** — If others contribute code, review it carefully before merging.

**Prompt for scheduled maintenance:**

```
Help me create scripts/update_knowledge_base.py that:
1. Can be run manually or on a schedule
2. Checks if any new source documents have been added to knowledge_base/sources/
3. Re-embeds and re-indexes any new or changed documents
4. Logs what was updated
5. Can be hooked into a cron job (scheduled task) for weekly updates
```

---

## 10. Appendix — Quick Reference Sheets

### 10.1 Essential Terminal Commands

| Command | What It Does |
|---|---|
| `cd folder_name` | Move into a folder |
| `cd ..` | Move up one folder level |
| `ls` (Mac/Linux) or `dir` (Windows) | List files in current folder |
| `pwd` (Mac/Linux) | Show current folder path |
| `mkdir folder_name` | Create a new folder |
| `cat file.txt` (Mac/Linux) | Display file contents |
| `python script.py` | Run a Python script |
| `pip install package_name` | Install a Python package |
| `pip freeze` | List all installed packages |
| `git status` | Show changed files |
| `git add .` | Stage all changes for commit |
| `git commit -m "message"` | Save a snapshot with a message |
| `git push` | Upload commits to GitHub |
| `git log --oneline` | Show commit history |

### 10.2 Essential Python Concepts to Know

As you work through this project, you will encounter these Python concepts. When you see one you don't understand, ask Claude Pro to explain it:

- **Variables and data types** (strings, integers, lists, dictionaries)
- **Functions** (reusable blocks of code with `def`)
- **Classes and objects** (blueprints for creating structured data)
- **Imports** (using code from other files with `import`)
- **Error handling** (try/except blocks)
- **List comprehensions** (compact ways to build lists)
- **Decorators** (the `@` symbol above functions)
- **Context managers** (the `with` keyword for file handling)
- **Async/await** (running tasks in parallel — used in some API calls)
- **Type hints** (annotations like `def greet(name: str) -> str:`)

### 10.3 Claude Pro Prompt Templates

**Quick-reference prompts you will use often:**

| Situation | Prompt Starter |
|---|---|
| Generate new code | "Write [filename] that does [requirements]. I am a beginner — add comments." |
| Fix an error | "I got this error: [paste error]. Here is my code: [paste code]. What's wrong?" |
| Understand code | "Explain this code line by line for a beginner: [paste code]" |
| Improve code | "Review this code and suggest improvements: [paste code]" |
| Write tests | "Write pytest tests for this code, including edge cases: [paste code]" |
| Connect two modules | "Show me how to use [module A] inside [module B]. Here are both files: [paste both]" |
| Refactor | "This code works but is messy. Clean it up while keeping the same behavior: [paste code]" |

### 10.4 Project Milestone Checklist

Use this to track your progress:

```
Phase 1 — Environment Setup
  □ Python 3.10+ installed and verified
  □ Git installed and verified
  □ VS Code installed with extensions
  □ Project folder created with virtual environment
  □ Folder structure skeleton created
  □ requirements.txt created and packages installed
  □ Git initialized with .gitignore and first commit
  □ .env.example and .env files created

Phase 2 — Claude Pro Preparation
  □ CLAUDE_CONTEXT.md written
  □ Practiced prompt patterns (generated at least one test file)

Phase 3 — Tool Integration
  □ AWS CLI installed and configured (or skipped for local-only mode)
  □ Ollama installed and Llama 3 model pulled (for local mode)
  □ ChromaDB installed (for local mode)
  □ HuggingFace sentence-transformers installed
  □ Configuration files created (settings.py, bedrock_config.py, logging_config.py)
  □ test_setup.py passes all checks

Phase 4 — Development (Sprint 1: Foundation)
  □ utils/exceptions.py complete and tested
  □ utils/file_utils.py complete and tested
  □ parsers/base_parser.py complete
  □ parsers/cloudformation_parser.py complete and tested
  □ parsers/resource_extractor.py complete and tested
  □ Git commit made

Phase 4 — Development (Sprint 2: Knowledge Base)
  □ Knowledge base source documents created
  □ knowledge_base/embeddings.py complete and tested
  □ knowledge_base/vector_store.py complete and tested
  □ knowledge_base/kb_manager.py complete and tested
  □ llm/bedrock_client.py complete and tested
  □ llm/prompt_templates.py complete
  □ llm/prompt_builder.py complete and tested
  □ llm/response_parser.py complete and tested
  □ Git commit made

Phase 4 — Development (Sprint 3: Agents)
  □ agents/base_agent.py complete
  □ agents/retrieval_agent.py complete and tested
  □ agents/vulnerability_detection_agent.py complete and tested
  □ agents/report_generation_agent.py complete and tested
  □ orchestrator/pipeline.py complete
  □ orchestrator/workflow_manager.py complete
  □ Git commit made

Phase 4 — Development (Sprint 4: Reporting)
  □ reporting/severity_classifier.py complete and tested
  □ reporting/markdown_formatter.py complete
  □ reporting/report_builder.py complete
  □ Report templates created
  □ Git commit made

Phase 5 — System Integration
  □ scripts/run_scan.py complete
  □ End-to-end test passes on test templates
  □ Reports generate correctly
  □ Git commit made

Phase 6 — Testing
  □ All unit tests written and passing
  □ Integration tests written and passing
  □ evaluate_results.py runs and produces metrics table
  □ Code coverage above 70%
  □ Manual testing checklist completed
  □ Git commit made

Phase 7 — Finalization
  □ Code cleaned up (no debug prints, all docstrings present)
  □ setup.py and Makefile created
  □ GitHub repository created and code pushed
  □ GitHub Actions CI/CD workflow active and passing
  □ .env file confirmed NOT in repository

Phase 8 — Documentation
  □ README.md complete and polished
  □ docs/setup_guide.md complete
  □ docs/architecture.md complete
  □ docs/agent_descriptions.md complete
  □ docs/api_reference.md complete
  □ CHANGELOG.md created
  □ Final Git commit and push
```

---

## Final Words

Building a software project from scratch without prior experience is challenging but entirely achievable. The key principles to remember:

- **One step at a time.** Never try to build two things simultaneously.
- **Test constantly.** Run your code after every change, no matter how small.
- **Commit often.** Every time something works, make a Git commit. This is your safety net.
- **Ask Claude Pro everything.** There is no question too basic. If you do not understand a line of code, ask about it.
- **Errors are normal.** Professional developers spend a significant portion of their time debugging. Every error you fix makes you a better developer.
- **Read your own code.** Even if Claude wrote it, make sure you understand what it does. This is how you learn.

You have a solid research paper, a clear architecture, and a powerful AI assistant. You are ready to build this. Good luck!

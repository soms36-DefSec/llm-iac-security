from setuptools import find_packages, setup

setup(
    name="llm-iac-security",
    version="0.1.0",
    description="LLM Agentic Workflow for Automated Vulnerability Detection and Remediation in IaC",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*", "scripts*"]),
    install_requires=[
        "boto3>=1.34.0",
        "pyyaml>=6.0.1",
        "pydantic>=2.6.0",
        "python-dotenv>=1.0.1",
        "tenacity>=8.2.3",
        "structlog>=24.1.0",
        "click>=8.1.7",
        "rich>=13.7.0",
        "requests>=2.31.0",
        "pypdf>=5.0.0",
    ],
    extras_require={
        "local": [
            "chromadb>=0.4.0",
            "sentence-transformers>=3.0.0",
        ],
        "aws": [
            "pinecone>=5.0.0",
        ],
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=5.0.0",
            "pytest-mock>=3.14.0",
            "flake8>=7.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={"console_scripts": ["iac-scan=scripts.run_scan:scan"]},
)

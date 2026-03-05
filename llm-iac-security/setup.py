from setuptools import find_packages, setup
setup(
    name="llm-iac-security",
    version="0.1.0",
    description="LLM Agentic Workflow for Automated Vulnerability Detection in IaC",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*", "scripts*"]),
    install_requires=[
        "boto3>=1.34.0", "pyyaml>=6.0.1", "pydantic>=2.6.0",
        "python-dotenv>=1.0.1", "tenacity>=8.2.3", "structlog>=24.1.0",
        "opensearch-py>=2.4.0", "click>=8.1.7", "rich>=13.7.0",
    ],
    entry_points={"console_scripts": ["iac-scan=scripts.run_scan:scan"]},
)

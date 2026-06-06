# GitLab Security Guardian

An autonomous Security Guardian project designed to continuously scan, monitor, and enforce security policies across GitLab repositories.

## Overview

The **GitLab Security Guardian** is an agentic, automated orchestrator built to scan codebases, detect exposed secrets, audit dependency vulnerabilities, and ensure compliance with security best practices.

## Orchestrator Language

We recommend and use **Python** for this orchestrator due to its:
- Native support for security tooling and CLI integration.
- Robust libraries for parsing, regex, and AST analysis.
- First-class support for AI/LLM integration (e.g., Google GenAI, OpenAI, LangChain).
- Clean scripting syntax ideal for DevSecOps pipelines.

## Features

- **Secrets Detection:** Automatic scanning for hardcoded API keys, passwords, and tokens.
- **Dependency Auditing:** Scanning project dependencies for known vulnerabilities.
- **Static Analysis (SAST):** Linting and static analysis of source code to find security flaws.
- **Policy Enforcement:** Verification that repository configurations and merge requests meet security standards.

## Getting Started

### Prerequisites
- Python 3.10+
- GitLab Personal Access Token (PAT) with API scopes

### Installation
1. Clone the repository:
   ```bash
   git clone https://gitlab.com/soft-hive-group/guardianagent-autonomous-gitlab-security-orchestrator.git
   cd guardianagent-autonomous-gitlab-security-orchestrator
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

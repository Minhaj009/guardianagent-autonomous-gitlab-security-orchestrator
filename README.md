# GitLab Security Guardian 🛡️

An autonomous, full-stack Security Orchestrator designed to continuously scan, monitor, automatically remediate, and enforce security policies across code repositories using Google Cloud Vertex AI.

---

## 🚀 Key Features

### 1. Vertex AI Gemini Ensemble Orchestrator
- **Multi-Model Ensemble**: Employs an ensemble of **Google Cloud Vertex AI Gemini models** (`gemini-1.5-pro` and `gemini-1.5-flash`) run concurrently with diverse temperature profiles and customized system prompt orientations:
  - **Gemini 1.5 Flash (Precision)**: Low temperature (0.1) for high-precision syntax issues and direct security risks.
  - **Gemini 1.5 Pro (Deep)**: Medium-low temperature (0.2) for deep logical path analysis, tracking data flows, and identifying subtle logic flaws.
  - **Gemini 1.5 Flash (Creative)**: Medium temperature (0.7) for wide architectural design issues, dependency vulnerabilities, and configuration flaws.
  - **Gemini 1.5 Pro (Logical)**: High temperature (0.8) for hidden race conditions, authorization flaws (IDOR), and cryptographic weaknesses.
- **Structured JSON Schema**: Leverages Vertex AI structured outputs with Pydantic schema enforcement to guarantee the returned security findings strictly comply with the expected list format.
- **Robust Exception Handling**: Gracefully ignores transient model failures and retries calls with exponential backoff using `tenacity`.
- **Environment Safety**: Authenticates securely via standard Google Cloud Credentials (OIDC/WIF or service accounts) without needing hardcoded keys, with `GITLAB_TOKEN` retrieved safely from environment variables.

### 2. Consensus & Confidence Engine
- **Consolidated Deduplication**: Groups identical scanner findings by file and line number across all ensemble models.
- **Mathematical Consensus**: Calculates a Consensus Score based on what percentage of the active ensemble models flagged the specific issue.
- **Gemini-Powered Synthesis**: Uses `gemini-1.5-pro` to synthesize diverse descriptions from different models into a single, cohesive, 1-3 sentence summary.

### 3. Auto-Remediation Engine (Phase 2)
- **High-Confidence Targeting**: Automatically targets any vulnerability with a Consensus Score of 30% or higher.
- **Conflict Marker Patching**: Queries `gemini-1.5-pro` to rewrite the code block securely, returning the patch formatted using standard conflict markers:
  ```diff
  <<<<<<< ORIGINAL
  [vulnerable code block]
  =======
  [corrected code block]
  >>>>>>> CORRECTED
  ```
- **Line-Shift Safeguard**: Sorts all file findings in descending line number order (highest to lowest) before applying patches to prevent line-shifting corruption.
- **Verify-before-Report Sequence**: Executes local file writes and verifies their readback success on-disk *before* compiling the final report, ensuring the report accurately reflects the real-world status.
- **Git Loop Prevention**: Commits and pushes the patches directly to the MR branch, appending `[skip ci]` to the commit message to prevent infinite CI pipelines.

### 4. Micro-SaaS Developer Platform (Milestone A)
A complete, premium web-based developer portal built under the `web/` subdirectory:
- **Tech Stack**: Express.js server, EJS templates, SQLite (`sqlite3`) local database, and session authentication (`bcryptjs` password hashing).
- **Tailwind CSS v4 Dark-Mode UI**: A glassmorphic dashboard featuring glowing background assets, dynamic metrics, and settings config to save user GCP parameters.
- **Simulated Demo Sandbox**: Interactive repository table switcher (`SoftHive-group/Internal-Tools` and `Guardian-Shield/Web-Portal`) allowing users to interact with live-feeling consensus reports out-of-the-box.
- **Tabbed Onboarding Guides**: Displays copyable YAML setup configurations for GitLab CI/CD and GitHub Actions.

---

## 📂 Project Structure

- `guardian.py`: The Python-based ensemble scanner and remediation orchestrator. Exposes both standard CLI interface and SSE/Stdio Model Context Protocol (MCP) server endpoints.
- `vulnerable_service.py`: A test service featuring 5 intentional flaws (AWS keys, SQL injection, Command injection, Pickle load, IDOR) used to test the consensus and remediation engines.
- `web/`: The Micro-SaaS Express.js platform.
  - `web/server.js`: Server routing and API logic.
  - `web/database.js`: SQLite connection, tables, and mock data.
  - `web/views/`: EJS frontend templates.
- `.gitlab-ci.yml`: CI configurations to run security jobs on MR events.
- `scripts/`: Helper scripts for deployment and WIF configuration.

---

## 🛠️ Getting Started

### 1. Run the Security Scanner Orchestrator
To run a manual orchestrator scan locally:
1. Export environment variables and log in to Google Cloud:
   ```bash
   export GITLAB_TOKEN="your-gitlab-token"
   gcloud auth application-default login
   ```
2. Run the script:
   ```bash
   python guardian.py --project-id "your-gitlab-project-id" --mr-iid <merge-request-iid> --gcp-project "your-gcp-project-id"
   ```

### 2. Run the Micro-SaaS Web Console
1. Navigate to the web folder:
   ```bash
   cd web
   ```
2. Run the server:
   ```bash
   node server.js
   ```
3. Open [http://localhost:3000](http://localhost:3000) in your browser. Register an account and configure your console!

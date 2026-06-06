# GitLab Security Guardian 🛡️

An autonomous, full-stack Security Orchestrator designed to continuously scan, monitor, automatically remediate, and enforce security policies across code repositories.

---

## 🚀 Key Features

### 1. Dynamic LLM Mega-Ensemble Orchestrator
- **Dynamic Model Discovery**: Queries the OpenRouter API dynamically to fetch all available free models (cost = 0 or `:free` suffix).
- **High Concurrency Scanning**: Utilizes a Python `ThreadPoolExecutor` with a pool size of 5 to concurrently dispatch MR code diffs to all free models, avoiding HTTP 429 Rate Limits.
- **Robust Exception Handling**: Gracefully ignores transient model failures (404, 429, 503) and cleans up DeepSeek R1 `<think>...</think>` tags to keep JSON parsing stable.
- **Environment Safety**: Credentials (`GITLAB_TOKEN` and `OPENROUTER_API_KEY`) are retrieved securely via environment variables instead of exposed CLI flags.

### 2. Consensus & Confidence Engine
- **Consolidated Deduplication**: Groups identical scanner findings by file and line number.
- **Mathematical Consensus**: Calculates a Consensus Score based on what percentage of the successful scanner models flagged the specific issue.
- **Llama-Powered Synthesis**: Calls `meta-llama/llama-3.3-70b-instruct:free` to synthesize various model descriptions into a single, cohesive, 1-3 sentence summary.

### 3. Auto-Remediation Engine (Phase 2)
- **High-Confidence Targeting**: Automatically targets any vulnerability with a Consensus Score of 30% or higher.
- **Conflict Marker Patching**: Queries Llama 3.3 to rewrite the code block securely, returning the patch formatted using standard conflict markers:
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
- **Tailwind CSS v4 Dark-Mode UI**: A glassmorphic dashboard featuring glowing background assets, dynamic metrics, and settings config to save user API keys.
- **Simulated Demo Sandbox**: Interactive repository table switcher (`SoftHive-group/Internal-Tools` and `Guardian-Shield/Web-Portal`) allowing users to interact with live-feeling consensus reports out-of-the-box.
- **Tabbed Onboarding Guides**: Displays copyable YAML setup configurations for GitLab CI/CD and GitHub Actions.

---

## 📂 Project Structure

- `guardian.py`: The Python-based ensemble scanner and remediation orchestrator.
- `vulnerable_service.py`: A test service featuring 5 intentional flaws (AWS keys, SQL injection, Command injection, Pickle load, IDOR) used to test the consensus and remediation engines.
- `web/`: The Micro-SaaS Express.js platform.
  - `web/server.js`: Server routing and API logic.
  - `web/database.js`: SQLite connection, tables, and mock data.
  - `web/views/`: EJS frontend templates.
- `.gitlab-ci.yml`: CI configurations to run security jobs on MR events.

---

## 🛠️ Getting Started

### 1. Run the Security Scanner Orchestrator
To run a manual orchestrator scan locally:
1. Export environment variables:
   ```bash
   export GITLAB_TOKEN="your-token"
   export OPENROUTER_API_KEY="your-key"
   ```
2. Run the script:
   ```bash
   python guardian.py --project-id "your-project-id" --mr-iid <merge-request-iid>
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

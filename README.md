# GitLab Security Guardian 🛡️

An autonomous, full-stack Security Orchestrator designed to continuously scan, monitor, automatically remediate, and enforce security policies across code repositories using Google Cloud Vertex AI.

---

## 🚀 Key Features

### 1. Vertex AI Gemini Ensemble Orchestrator
- **Multi-Model Ensemble**: Employs an ensemble of **Google Cloud Vertex AI Gemini models** (`gemini-2.0-flash`, `gemini-2.0-pro`, `gemini-2.5-flash`, and `gemini-2.5-pro`) run concurrently with diverse temperature profiles and customized system prompt orientations:
  - **Gemini Flash (Precision)**: Low temperature (0.1) for high-precision syntax issues and direct security risks.
  - **Gemini Pro (Deep)**: Medium-low temperature (0.2) for deep logical path analysis, tracking data flows, and identifying subtle logic flaws.
  - **Gemini Flash (Creative)**: Medium temperature (0.7) for wide architectural design issues, dependency vulnerabilities, and configuration flaws.
  - **Gemini Pro (Logical)**: High temperature (0.8) for hidden race conditions, authorization flaws (IDOR), and cryptographic weaknesses.
- **Structured JSON Schema**: Leverages Vertex AI structured outputs with Pydantic schema enforcement to guarantee the returned security findings strictly comply with the expected list format.
- **Robust Exception Handling**: Gracefully ignores transient model failures and retries calls with exponential backoff using `tenacity`.
- **Environment Safety**: Authenticates securely via standard Google Cloud Credentials (OIDC/WIF or service accounts) without needing hardcoded keys.

### 2. Consensus & Confidence Engine
- **Consolidated Deduplication**: Groups identical scanner findings by file and line number across all ensemble models.
- **Mathematical Consensus**: Calculates a Consensus Score based on what percentage of the active ensemble models flagged the specific issue.
- **Gemini-Powered Synthesis**: Uses `gemini-2.0-pro`/`gemini-2.5-pro` to synthesize diverse descriptions from different models into a single, cohesive, 1-3 sentence summary.

### 3. Auto-Remediation Engine
- **High-Confidence Targeting**: Automatically targets any vulnerability with a Consensus Score of 30% or higher.
- **Conflict Marker Patching**: Queries Gemini to rewrite the code block securely, returning the patch formatted using standard conflict markers:

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

### 4. Live Developer Portal (Google Cloud Hosted)
A complete, premium web-based developer portal deployed on Google Cloud Run:
- **GitLab Account Integration**: Connect your GitLab Personal Access Token (PAT) with `api`, `read_repository`, and `write_repository` scopes.
- **Dynamic Repository Management**: Fetches and lists all repositories you are a member of, allowing you to toggle active repository connections with a single click.
- **On-Demand Manual Scans**: Trigger an autonomous security scan on any active repository and Merge Request (MR) directly from the Web Console dashboard.
- **Interactive Security Activity Feed**: Review live branch remediations, view side-by-side diff comparisons of vulnerable vs. secure code, approve/commit patches directly to your branches, or reject patches. Includes a thumb-up/down feedback system to rate agent patches.
- **Premium Glassmorphic UI**: High-end Tailwind-based developer console with animated state flows and real-time metric updates.

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

## 🛠️ Getting Started with the Cloud Console

To use the live, hosted GitLab Security Guardian:

1. **Access the Web Console**:
   Open the live developer portal at [https://guardian-web-console-441097947190.us-central1.run.app](https://guardian-web-console-441097947190.us-central1.run.app) and register/log in to your account.

2. **Connect your GitLab Account**:
   - Go to **GitLab Setup** in the top navigation.
   - Enter a GitLab Personal Access Token (PAT). Make sure the token is created with the `api`, `read_repository`, and `write_repository` scopes enabled.
   - Click **Link GitLab Account**.

3. **Activate Repositories**:
   - Once connected, the console will dynamically fetch and list the repositories you belong to.
   - Toggle the switch to **Active** for any repository you want to monitor and scan.

4. **Trigger a Scan**:
   - Go back to the **Review Dashboard**.
   - Under the **Trigger Manual Security Scan** panel, enter your GitLab Project Path (e.g. `minhaajislamm/EduGenius`) and the **Merge Request IID** (Internal ID).
   - Click **Run Security Scan**.
   - The dashboard will poll in the background while the Vertex AI agent ensemble reviews the merge request. Once complete, findings and proposed secure patches will appear in your **Security Activity Feed** where you can approve/commit them to your branch with a single click.

---

## 💻 Local Development Setup (Optional)

If you wish to run the orchestrator script or web console locally for testing or development:

### Prerequisites
- Python 3.11+
- Node.js 18+
- Google Cloud SDK (`gcloud` CLI) authenticated to a GCP project with the Vertex AI API enabled.

### 1. Run the Security Scanner Orchestrator CLI
1. Clone the repository and install the dependencies:
   ```bash
   pip install requests google-genai tenacity
   ```
2. Export your GitLab token and authenticate with GCP:
   ```bash
   export GITLAB_TOKEN="your-gitlab-token"
   gcloud auth application-default login
   ```
3. Run a scan manually against a specific GitLab project and Merge Request:
   ```bash
   python guardian.py --project-id "your-gitlab-project-path" --mr-iid <merge-request-iid> --gcp-project "your-gcp-project-id"
   ```

### 2. Run the Web Console Locally
1. Navigate to the `web/` folder and install dependencies:
   ```bash
   cd web
   npm install
   ```
2. Start the local Express server:
   ```bash
   node server.js
   ```
3. Open `http://localhost:3000` in your browser. Register an account and connect your GitLab token to start testing.

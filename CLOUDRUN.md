# 🚀 Deploying GitLab Security Guardian to Google Cloud Run

This guide details the steps to build, containerize, and deploy both the **SaaS Web Console** and the **Python MCP Security Scanner** to Google Cloud Run, adhering to Google Cloud Run best practices.

---

## 🏗️ Architecture Overview

Google Cloud Run is a fully managed serverless platform that automatically scales your containerized applications. We deploy the project as two separate services:

1. **Dashboard Web Console**: An Express.js node application rendering the security feed and user settings.
2. **Security Runner (Remote MCP Server)**: A Python service exposing the ensemble security scanner as a remote model-to-model (SSE) or command-line (Stdio) agentic interface.

```
   [ GitLab Webhooks / Devs ]
               │
               ▼
┌──────────────────────────────┐
│  Cloud Run: Web Dashboard    │
│  (Port 3000, Express + EJS)  │
└──────────────┬───────────────┘
               │ Reports Scans via JSON API
               ▼
┌──────────────────────────────┐
│  Cloud Run: Python MCP SSE   │
│  (Port 8000, Vertex AI SDK)  │
└──────────────────────────────┘
```

---

## 📦 Containerizing the Services

We use separate, optimized Dockerfiles for both services.

### 1. Web Console (`Dockerfile`)
The Web Console container uses a lightweight Alpine Node.js image, installs only production dependencies, and runs on port `3000`.

### 2. Python Security Scanner (`Dockerfile.guardian`)
The Python orchestrator container runs on Python 3.10-slim. It installs the Vertex AI GenAI SDK and packs the `git` client required to clone and checkout branches for patch operations.

---

## 🚀 Deploying to Google Cloud Run

Ensure you have the Google Cloud CLI (`gcloud`) installed and authenticated.

### Step 1: Set Up Artifact Registry
Create a repository to host your Docker images:
```bash
gcloud artifacts repositories create guardian-repo \
    --repository-format=docker \
    --location=us-central1 \
    --description="GitLab Security Guardian Docker Repo"
```

### Step 2: Build and Push Container Images
Build the images using Google Cloud Build (or locally and push):
```bash
# Build Web Console
gcloud builds submit --tag us-central1-docker.pkg.dev/YOUR_PROJECT_ID/guardian-repo/web-console:latest .

# Build Python Runner
gcloud builds submit --config cloudbuild-guardian.yaml --tag us-central1-docker.pkg.dev/YOUR_PROJECT_ID/guardian-repo/python-runner:latest -f Dockerfile.guardian .
```

### Step 3: Deploy the Web Console
Deploy the Express.js app as a public Web Service:
```bash
gcloud run deploy guardian-web-console \
    --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/guardian-repo/web-console:latest \
    --platform=managed \
    --region=us-central1 \
    --allow-unauthenticated \
    --port=3000 \
    --set-env-vars="SECRET_ENCRYPTION_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
```

### Step 4: Deploy the Python MCP Scanner (SSE Mode)
To host the runner as a remote SSE MCP server, deploy the container and override the startup arguments:
```bash
gcloud run deploy guardian-mcp-runner \
    --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/guardian-repo/python-runner:latest \
    --platform=managed \
    --region=us-central1 \
    --port=8000 \
    --args="--mcp-sse","--mcp-port","8000","--gcp-project","YOUR_PROJECT_ID" \
    --set-env-vars="GITLAB_TOKEN=your-gitlab-token,GUARDIAN_PORTAL_URL=https://your-web-console-url"
```

---

## 💡 Cloud Run Deployment Best Practices

### 1. SQLite Statefulness Warning
Google Cloud Run instances are stateless and ephemeral. The SQLite database (`guardian.db`) will reset whenever the container scales down to zero or restarts.
*   **For Demos/Testing**: The built-in SQLite database works out-of-the-box.
*   **For Production**: 
    1. Migrate `web/database.js` to a hosted database (such as **Google Cloud SQL for PostgreSQL**).
    2. Alternatively, mount a persistent directory using **Cloud Storage FUSE** to store `guardian.db` persistently.

### 2. Secret Management
Never expose credentials like `GITLAB_TOKEN` or Google Cloud service account keys in plain text environment variables. 
*   Use **Google Cloud Secret Manager**.
*   Mount secrets directly into your Cloud Run service:
    ```bash
    gcloud run deploy guardian-web-console \
        --update-secrets="GITLAB_TOKEN=gitlab-token-secret:latest"
    ```

### 3. Service Account IAM Permissions
Ensure the service account running your Python runner has Vertex AI permissions. Grant the following IAM role to the service account:
*   `roles/aiplatform.user` (Vertex AI User)

### 4. Logging & Observability
All standard outputs (`print` and `logger.info`) are automatically ingested by **Cloud Logging**. You can inspect scan operations, API calls, and Git branch pushes directly via the Google Cloud Console Logs Explorer.

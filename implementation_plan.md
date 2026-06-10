# Implementation Plan - Micro-SaaS Portal & Model Upgrades

Refactor the GuardianAgent web portal to transition it into a clean, consumer-oriented Micro-SaaS and upgrade the underlying AI models to the Gemini 2.x/2.5 generation. We will remove client-side GCP credentials configuration (the app will run entirely using our hosted backend GCP/Vertex credentials) and strip telemetry/integration bloat (e.g. 15 models, GitHub).

## Proposed Changes

### [Core Analyzer Upgrade]

#### [MODIFY] [guardian.py](file:///f:/gitlab-security-guardian/guardian.py)
- Upgrade the ensemble configurations in `get_ensemble_models()` to use the latest **Gemini 2.5/2.0** models:
  - Replace `gemini-1.5-flash` with `gemini-2.0-flash` (or `gemini-2.5-flash` depending on API availability).
  - Replace `gemini-1.5-pro` with `gemini-2.0-pro` (or `gemini-2.5-pro`).
- Update description synthesis (`synthesize_descriptions_with_llm`) and remediation patch generator (`generate_remediation_patch`) to use `gemini-2.0-pro` / `gemini-2.5-pro`.

---

### [Web Portal Frontend]

#### [MODIFY] [dashboard.ejs](file:///f:/gitlab-security-guardian/web/views/dashboard.ejs)
- Remove `GitHub Setup` link from the header navigation.
- Remove "Demo Sandbox Active" status references; default the header status label to "Live Audit Connected".
- Refactor the KPI Metrics Grid:
  - Remove the **"Active LLM Ensemble" (15 Models)** card.
  - Dynamically align the remaining 3 cards (Vulnerabilities Found, Patches Pushed, Branches Tested).
- Remove the **"Google Cloud & Agent Configuration Settings Panel"** entirely from the dashboard UI so consumers don't need to specify their own service account JSON key credentials.
- Keep the **"Trigger Manual Security Scan"** and **"Security Activity Feed"** panels, as well as the console log view at the bottom.

#### [MODIFY] [gitlab.ejs](file:///f:/gitlab-security-guardian/web/views/gitlab.ejs)
- Remove `GitHub Setup` link from the header navigation.
- Simplify step descriptions: remove complex GCP/WIF setup guidelines since the SaaS handles the cloud analysis resources entirely. Only instruct the user to configure the `GITLAB_TOKEN` and `GUARDIAN_USER_ID`.

---

### [Web Portal Backend]

#### [MODIFY] [server.js](file:///f:/gitlab-security-guardian/web/server.js)
- Ensure background scan triggers (`/api/scans/trigger`) fallback directly to the hosted server-side `GCP_PROJECT_ID` and region environment credentials instead of querying user-submitted database records.
- Simplify dashboard rendering variables so `isDemoMode` is cleanly set to false/true depending on database scans.

## Verification Plan

### Manual Verification
- Run the node server locally (`node server.js` or `npm run dev`) and navigate the dashboard:
  - Verify `GitHub Setup` is gone.
  - Verify the GCP panel is hidden.
  - Verify metrics show a 3-column layout.
- Dry-run a manual scan to ensure model identifiers parse correctly without API exceptions.

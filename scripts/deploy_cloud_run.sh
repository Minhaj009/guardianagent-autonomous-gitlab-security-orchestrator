#!/usr/bin/env bash
# deploy_cloud_run.sh
# Automates the container build and deployment of the GuardianAgent Web Portal to Google Cloud Run.

set -e

# Configuration
GCP_PROJECT_ID=$(gcloud config get-value project)
GCP_REGION="us-central1"
SERVICE_NAME="guardian-web-console"
IMAGE_TAG="us-central1-docker.pkg.dev/${GCP_PROJECT_ID}/guardian-repo/web-console:latest"

echo "================================================================="
echo "Deploying GuardianAgent Web Console to Google Cloud Run"
echo "Project ID:   $GCP_PROJECT_ID"
echo "Region:       $GCP_REGION"
echo "Service Name: $SERVICE_NAME"
echo "Image Tag:    $IMAGE_TAG"
echo "================================================================="

# 1. Enable Required GCP APIs
echo "Enabling Cloud Run and Cloud Build APIs..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com --project="$GCP_PROJECT_ID"

# 2. Build image using Cloud Build
echo "Submitting build to Cloud Build..."
# Run build from project root, specifying 'web' directory context
gcloud builds submit --tag "$IMAGE_TAG" ./web --project="$GCP_PROJECT_ID"

# Fetch the MCP runner URL dynamically to configure the web console link
echo "Retrieving guardian-mcp-runner URL..."
MCP_SERVICE_URL=$(gcloud run services describe guardian-mcp-runner --platform managed --region "$GCP_REGION" --format="value(status.url)" --project="$GCP_PROJECT_ID" 2>/dev/null || echo "")
if [ -z "$MCP_SERVICE_URL" ]; then
  echo "Warning: Could not retrieve guardian-mcp-runner URL. Using fallback."
  MCP_SERVICE_URL="https://guardian-mcp-runner-${GCP_PROJECT_ID}.us-central1.run.app"
fi

# 3. Deploy to Cloud Run
echo "Deploying container image to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE_TAG" \
  --platform managed \
  --region "$GCP_REGION" \
  --allow-unauthenticated \
  --set-env-vars="SECRET_ENCRYPTION_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6,GCP_PROJECT_ID=${GCP_PROJECT_ID},GCP_LOCATION=${GCP_REGION},GUARDIAN_MCP_URL=${MCP_SERVICE_URL}" \
  --project="$GCP_PROJECT_ID"


# 4. Get the service URL
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --platform managed --region "$GCP_REGION" --format="value(status.url)" --project="$GCP_PROJECT_ID")

echo "================================================================="
echo "Deployment Successful!"
echo "Service URL: $SERVICE_URL"
echo "================================================================="
echo "Note: Define GUARDIAN_PORTAL_URL=$SERVICE_URL in your GitLab CI"
echo "variables so the pipeline runner can report findings back to this live URL."
echo "================================================================="

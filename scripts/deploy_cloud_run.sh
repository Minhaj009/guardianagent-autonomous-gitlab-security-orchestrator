#!/usr/bin/env bash
# deploy_cloud_run.sh
# Automates the container build and deployment of the GuardianAgent Web Portal to Google Cloud Run.

set -e

# Configuration
GCP_PROJECT_ID=$(gcloud config get-value project)
GCP_REGION="us-central1"
SERVICE_NAME="guardian-web"
IMAGE_TAG="gcr.io/${GCP_PROJECT_ID}/${SERVICE_NAME}:latest"

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

# 3. Deploy to Cloud Run
echo "Deploying container image to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE_TAG" \
  --platform managed \
  --region "$GCP_REGION" \
  --allow-unauthenticated \
  --set-env-vars="SECRET_ENCRYPTION_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" \
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

#!/usr/bin/env bash
# setup_gcp_wif.sh
# Automates Google Cloud Workload Identity Federation (WIF) setup for keyless GitLab CI/CD pipelines.

set -e

# Configuration variables
GCP_PROJECT_ID=$(gcloud config get-value project)
GCP_PROJECT_NUMBER=$(gcloud projects describe "$GCP_PROJECT_ID" --format="value(projectNumber)")
POOL_ID="gitlab-pool"
PROVIDER_ID="gitlab-provider"
SERVICE_ACCOUNT_NAME="gitlab-runner-sa"
SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

echo "================================================================="
echo "Configuring GCP Workload Identity Federation for GitLab"
echo "Project ID:      $GCP_PROJECT_ID"
echo "Project Number:  $GCP_PROJECT_NUMBER"
echo "================================================================="

# 1. Create the Workload Identity Pool
if ! gcloud iam workload-identity-pools describe "$POOL_ID" --location="global" &>/dev/null; then
  echo "Creating Workload Identity Pool: $POOL_ID..."
  gcloud iam workload-identity-pools create "$POOL_ID" \
    --location="global" \
    --display-name="GitLab CI/CD Pool" \
    --description="Pool for GitLab CI/CD runner keyless authentication"
else
  echo "Workload Identity Pool: $POOL_ID already exists."
fi

# 2. Create the OIDC Workload Identity Provider
if ! gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" \
  --workload-identity-pool="$POOL_ID" --location="global" &>/dev/null; then
  
  echo "Creating OIDC Provider: $PROVIDER_ID..."
  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
    --location="global" \
    --workload-identity-pool="$POOL_ID" \
    --display-name="GitLab Provider" \
    --attribute-mapping="google.subject=assertion.sub,attribute.project_path=assertion.project_path,attribute.project_id=assertion.project_id,attribute.user_email=assertion.user_email" \
    --issuer-uri="https://gitlab.com" \
    --allowed-audiences="https://iam.googleapis.com"
else
  echo "OIDC Provider: $PROVIDER_ID already exists."
fi

# 3. Create the Service Account
if ! gcloud iam service-accounts describe "$SERVICE_ACCOUNT_EMAIL" &>/dev/null; then
  echo "Creating Service Account: $SERVICE_ACCOUNT_NAME..."
  gcloud iam service-accounts create "$SERVICE_ACCOUNT_NAME" \
    --display-name="GitLab CI/CD Runner Service Account"
else
  echo "Service Account: $SERVICE_ACCOUNT_EMAIL already exists."
fi

# 4. Bind the Service Account to the Workload Identity Provider
# Grant access to any repository in the user's GitLab namespace/project
echo "Binding Workload Identity Provider to Service Account..."
gcloud iam service-accounts add-iam-policy-binding "$SERVICE_ACCOUNT_EMAIL" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/*"

# 5. Grant the Service Account Vertex AI User access on the project
echo "Granting Vertex AI User role to Service Account..."
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/aiplatform.user"

# Generate client credential config file template
echo "Generating credential configuration helper..."
gcloud iam workload-identity-pools create-cred-config \
  "projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}" \
  --service-account="$SERVICE_ACCOUNT_EMAIL" \
  --output-file="gcp-wif-creds-template.json" \
  --credential-source-file="gitlab-token.txt"

echo "================================================================="
echo "WIF Setup Successful!"
echo "Service Account: $SERVICE_ACCOUNT_EMAIL"
echo "Workload Pool:   projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}"
echo "================================================================="
echo "Instructions for your GitLab CI/CD (.gitlab-ci.yml) config:"
echo "1. Define GITLAB_OIDC_TOKEN using id_tokens"
echo "2. Echo \$GITLAB_OIDC_TOKEN > gitlab-token.txt"
echo "3. Replace project number/ID in gcp-wif-creds-template.json and save as gcp-creds.json"
echo "4. Export GOOGLE_APPLICATION_CREDENTIALS=gcp-creds.json"
echo "================================================================="

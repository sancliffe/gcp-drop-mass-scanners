#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_NAME="default"
RULE_NAME="network-drop-hydracomms"

# --- IP BLOCKS TO BLOCK (Hydra Communications / AS25369) ---
# Note: AS25369 announces ~200+ prefixes. Included here are the largest ones.
# GCP limits a single firewall rule to a maximum of 256 source ranges.
TARGET_RANGES=(
  "89.191.96.0/20"
  "217.146.80.0/20"
  "81.19.208.0/20"
  "178.239.160.0/20"
  "5.226.136.0/21"
  "78.143.224.0/21"
  "109.70.144.0/21"
  "46.231.160.0/21"
  "69.5.168.0/21"
  "109.69.104.0/21"
)

# Join the array elements into a comma-separated string
SOURCE_RANGES=$(IFS=,; echo "${TARGET_RANGES[*]}")

echo "Checking if firewall rule '${RULE_NAME}' already exists..."

# Check if the rule exists
if gcloud compute firewall-rules describe "$RULE_NAME" --project="$PROJECT_ID" &>/dev/null; then
  echo "Rule exists. Updating the source ranges..."
  gcloud compute firewall-rules update "$RULE_NAME" \
    --project="$PROJECT_ID" \
    --source-ranges="$SOURCE_RANGES"
else
  echo "Rule does not exist. Creating a new DENY rule..."
  gcloud compute firewall-rules create "$RULE_NAME" \
    --project="$PROJECT_ID" \
    --network="$NETWORK_NAME" \
    --action=DENY \
    --rules=all \
    --direction=INGRESS \
    --priority=12 \
    --source-ranges="$SOURCE_RANGES" \
    --description="Drop traffic from Hydra Communications (AS25369)."
fi

echo "Hydra Communications firewall block deployed."

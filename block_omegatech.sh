#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_NAME="default"
RULE_NAME="network-drop-omegatech"

# --- IP BLOCKS TO BLOCK (Omegatech LTD / AS202412) ---
TARGET_RANGES=(
    "158.94.208.0/21"  # Primary Omegatech routing block covering 158.94.210.x
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
        --description="Drop malicious traffic from Omegatech LTD (AS202412)."
fi

echo "Omegatech firewall block deployed."

#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID="project-67b89d13-0fb7-47c0-92b"
NETWORK_NAME="default"
RULE_NAME="network-drop-vdsina"

# --- IP BLOCKS TO BLOCK (VDSina / Unmanaged LTD) ---
TARGET_RANGES=(
    "193.32.162.0/24"  # Captured from your Fail2Ban logs (193.32.162.193)
    "62.113.112.0/20"  # Known VDSina AS48282 primary block
    "178.18.224.0/20"  # Known VDSina AS216071 primary block
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
        --priority=11 \
        --source-ranges="$SOURCE_RANGES" \
        --description="Drop malicious traffic from VDSina (Russian Federation)."
fi

echo "VDSina firewall block deployed."

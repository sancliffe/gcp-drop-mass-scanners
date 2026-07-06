#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_name="default"
RULE_NAME="network-drop-mass-scanners"

# --- IP BLOCKS TO BLOCK ---
TARGET_RANGES=(
    "184.105.136.0/22"   # Hurricane Electric / Network Indexers
    "141.212.0.0/16"     # Censys Scanning Subnets
    "162.243.128.0/19"   # DigitalOcean Scanner Blocks
    "71.6.232.0/24"      # CariNet Scanning Block
    "94.102.49.0/24"     # Shodan Census Indexing Block
    "65.49.1.0/24"       # Shadowserver Secondary Block
    "35.203.210.0/24"    # Palo Alto Networks / Cortex Xpanse Scanners
    "18.116.101.0/24"    # VisionHeight / AWS Commercial Scanners
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
        --network="$NETWORK_name" \
        --action=DENY \
        --rules=all \
        --direction=INGRESS \
        --priority=10 \
        --source-ranges="$SOURCE_RANGES" \
        --description="Drop persistent mass-scanners and network indexers at the edge."
fi

echo "Firewall infrastructure update complete."

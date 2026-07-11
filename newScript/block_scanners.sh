#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_NAME="default"
RULE_NAME="network-drop-mass-scanners"
BLACKLIST_FILE="blacklist.txt"

# Handle arguments
DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "!!! DRY RUN MODE ACTIVE - No changes will be applied !!!"
fi

# Validate blacklist exists
if [ ! -f "$BLACKLIST_FILE" ]; then
    echo "Error: $BLACKLIST_FILE not found."
    exit 1
fi

# --- DATA PROCESSING ---
# 1. Strip comments, empty lines, and extract the first column (IP/CIDR)
# 2. Join into a comma-separated list
SOURCE_RANGES=$(grep -v '^#' "$BLACKLIST_FILE" | grep -v '^\s*$' | awk '{print $1}' | paste -sd, -)

if [ -z "$SOURCE_RANGES" ]; then
    echo "Error: No valid ranges found in $BLACKLIST_FILE."
    exit 1
fi

# --- DEPLOYMENT ---
if [ "$DRY_RUN" = true ]; then
    echo "Would apply the following ranges:"
    echo "$SOURCE_RANGES"
    exit 0
fi

echo "Deploying firewall rule '${RULE_NAME}'..."

if gcloud compute firewall-rules describe "$RULE_NAME" --project="$PROJECT_ID" &>/dev/null; then
    echo "Rule exists. Updating ranges..."
    gcloud compute firewall-rules update "$RULE_NAME" \
        --project="$PROJECT_ID" \
        --source-ranges="$SOURCE_RANGES"
else
    echo "Rule does not exist. Creating..."
    gcloud compute firewall-rules create "$RULE_NAME" \
        --project="$PROJECT_ID" \
        --network="$NETWORK_NAME" \
        --action=DENY \
        --rules=all \
        --direction=INGRESS \
        --priority=10 \
        --enable-logging \
        --source-ranges="$SOURCE_RANGES" \
        --description="Drop persistent mass-scanners (via blocklist)."
fi

echo "Deployment complete. Monitor traffic in GCP Cloud Logging."

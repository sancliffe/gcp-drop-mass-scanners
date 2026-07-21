#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_NAME="default"
RULE_NAME="network-drop-attackers"
BLACKLIST_FILE="blacklist-attackers.txt"
MAX_CHARS=7000 # Warning threshold for GCP firewall rule character limit

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
# 1. sed: Remove everything from '#' to the end of the line (cleans inline comments)
# 2. awk: Only print lines that start with a number (handles headers and empty lines)
# 3. paste: Join with commas
SOURCE_RANGES=$(sed 's/#.*//' "$BLACKLIST_FILE" | awk '/^[0-9]/ {print $1}' | paste -sd, -)

if [ -z "$SOURCE_RANGES" ]; then
    echo "Error: No valid IP/CIDR ranges found in $BLACKLIST_FILE."
    exit 1
fi

# --- SAFETY CHECKS ---
CURRENT_LEN=${#SOURCE_RANGES}
echo "Blacklist generated ($CURRENT_LEN characters)."
if [ "$CURRENT_LEN" -gt "$MAX_CHARS" ]; then
    echo "WARNING: Your blacklist is nearing the GCP firewall rule character limit ($MAX_CHARS)."
    echo "Consider migrating to a Network Firewall Policy."
fi

# --- DEPLOYMENT ---
if [ "$DRY_RUN" = true ]; then
    echo "--- DRY RUN: Would apply the following ranges ---"
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

echo "Deployment complete."

#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_NAME="default"
RULE_NAME="network-drop-lordvps"

# --- IP BLOCKS TO BLOCK (LORDVPS / AS209425) ---
# Observed source of repeated postscreen PREGREET failures against postfix
# on free-tier-vm (2026-07-15). RIPE allocation IR-LORDVPS11-20240618,
# registrant "Atis Omran Sevin PSJ", Tehran, IR. Low-reputation VPS range,
# generic Gmail abuse contact, listed on AbuseIPDB.
TARGET_RANGES=(
  "81.30.98.0/24"
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
    --description="Drop traffic from LORDVPS range (AS209425) - mail scanning/PREGREET spam source."
fi

echo "LORDVPS firewall block deployed."

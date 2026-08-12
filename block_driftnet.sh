#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_NAME="default"
RULE_NAME="network-drop-driftnet"

# --- IP BLOCKS TO BLOCK (DRIFTNET) ---
# Identified via AbuseIPDB enrichment: every entry below carries ASN 211298
# ("DRIFTNET - Driftnet Ltd, GB", owner handle UK-DRIFTNET-*) and resolves
# via reverse DNS to "*.monitoring.internet-measurement.com". Driftnet
# operates internet-measurement/monitoring probes. All entries carry an
# AbuseIPDB confidence score of 100 with hundreds of reports each as of the
# lookup date (2026-08-09, server_connections09072026_enriched.csv).
TARGET_RANGES=(
  "87.236.176.59/32"    # r3-59-3b.monitoring.internet-measurement.com
  "87.236.176.61/32"    # r3-61-3d.monitoring.internet-measurement.com
  "87.236.176.80/32"    # r3-80-50.monitoring.internet-measurement.com
  "185.247.137.4/32"    # r4-4-4.monitoring.internet-measurement.com
  "185.247.137.45/32"   # r4-45-2d.monitoring.internet-measurement.com
  "185.247.137.48/32"   # r4-48-30.monitoring.internet-measurement.com
  "185.247.137.49/32"   # r4-49-31.monitoring.internet-measurement.com
  "185.247.137.72/32"   # r4-72-48.monitoring.internet-measurement.com
  "185.247.137.80/32"   # r4-80-50.monitoring.internet-measurement.com
  "185.247.137.131/32"     # r4-131-83.monitoring.internet-measurement.com
  "185.247.137.150/32"  # r4-150-96.monitoring.internet-measurement.com
  "195.96.139.45/32"    # r5-45-2d.monitoring.internet-measurement.com
  "195.96.139.51/32"    # r5-51-33.monitoring.internet-measurement.com
  "195.96.139.59/32"    # r5-59-3b.monitoring.internet-measurement.com
  "195.96.139.69/32"    # r5-69-45.monitoring.internet-measurement.com
  "195.96.139.80/32"    # r5-80-50.monitoring.internet-measurement.com
  "195.96.139.81/32"    # r5-81-51.monitoring.internet-measurement.com
  "195.96.139.82/32"    # r5-82-52.monitoring.internet-measurement.com
  "195.96.139.87/32"    # r5-87-57.monitoring.internet-measurement.com
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
    --description="Drop traffic from Driftnet Ltd monitoring/scanning ranges (AS211298) - identified by *.monitoring.internet-measurement.com PTR records, AbuseIPDB score 100."
fi

echo "Driftnet firewall block deployed."

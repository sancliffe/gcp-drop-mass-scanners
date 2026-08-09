#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_NAME="default"
RULE_NAME="network-drop-stretchoid"

# --- IP BLOCKS TO BLOCK (STRETCHOID) ---
# Identified via AbuseIPDB enrichment by reverse-DNS pattern: every entry
# below resolves to a "*.stretchoid.com" PTR record. Stretchoid is a known
# mass internet-scanning operation; all ranges sit inside Microsoft ASN 8075
# (Azure), which it rents for scanning infrastructure. All ranges carry an
# AbuseIPDB confidence score of 100 with hundreds to thousands of reports
# each as of the lookup date.
# First 18 identified 2026-08-09 (blacklist-scanners_enriched.csv); next 2
# added 2026-08-09 (blacklist-attackers_enriched.csv); final 7 added
# 2026-08-09 (blacklist-scanners_enriched.csv re-upload).
TARGET_RANGES=(
  "9.234.8.52/32"       # azpdcgjpwmec.stretchoid.com
  "20.29.23.166/32"     # azpdcg9mstn5.stretchoid.com
  "20.64.105.0/24"      # azpdsg6i54lg.stretchoid.com
  "20.65.137.167/32"    # azpdsg1s0zlq.stretchoid.com
  "20.65.193.0/24"      # azpdsskg4j6v.stretchoid.com
  "20.65.195.108/32"    # azpdss9nwu1g.stretchoid.com
  "20.98.164.209/32"    # azpdcgxpolat.stretchoid.com
  "20.106.57.131/32"    # azpdcgx1inou.stretchoid.com
  "20.121.123.108/32"   # azpdesmn15tp.stretchoid.com
  "20.121.139.67/32"    # azpdegzeumc2.stretchoid.com
  "20.163.32.0/24"      # azpdwscai8sn.stretchoid.com
  "20.163.38.129/32"    # azpdws65gd2r.stretchoid.com
  "20.163.74.20/32"     # azpdwsg9w8ks.stretchoid.com
  "20.168.0.218/32"     # azpdwes133xm.stretchoid.com
  "20.168.7.107/32"     # azpdwgjvh4wl.stretchoid.com
  "20.168.121.44/32"    # azpdwgn6lr4w.stretchoid.com
  "20.168.123.0/24"     # azpdwgzchlzq.stretchoid.com
  "20.169.105.0/24"     # azpdwsgcmd10.stretchoid.com
  "74.235.100.212/32"   # azpdes7yclie.stretchoid.com
  "74.249.128.83/32"    # azpdcsn332nk.stretchoid.com
  "48.217.87.78/32"     # azpdeese2qqv.stretchoid.com
  "57.151.99.69/32"     # azpdegwuj3ef.stretchoid.com
  "74.249.128.108/32"   # azpdcgshpipk.stretchoid.com
  "135.119.96.214/32"   # azpdcgalskvn.stretchoid.com
  "135.237.124.78/32"   # azpdegbmiu12.stretchoid.com
  "172.210.9.231/32"    # azpdeskyhklc.stretchoid.com
  "172.210.68.2/32"     # azpdesj0pi01.stretchoid.com
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
    --description="Drop traffic from Stretchoid scanning ranges (Azure/AS8075) - identified by *.stretchoid.com PTR records, AbuseIPDB score 100."
fi

echo "Stretchoid firewall block deployed."

#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- CONFIGURATION ---
PROJECT_ID=""
NETWORK_name="default"
RULE_NAME="network-drop-mass-scanners"

# --- IP BLOCKS TO BLOCK THAT HAVE SCANNED MY VM INSTANCE ---
TARGET_RANGES=(
    "184.105.136.0/22"   # Hurricane Electric
    "141.212.0.0/16"     # Censys
    "162.243.128.0/19"   # DigitalOcean
    "71.6.232.0/24"       # CariNet
    "94.102.49.0/24"     # Shodan
    "65.49.1.0/24"       # Shadowserver
    "35.203.210.0/23"    # Palo Alto Cortex Xpanse (Expanded to /23 to catch 211.x)
    "18.116.101.0/24"    # VisionHeight
    "94.26.106.0/24"     # Add New: Persistent scanner block seen on July 7th
    "216.180.246.0/24"   # Nokia Deepfield Scanners
 
    # --- Added: newly identified scanners/research projects from fail2ban log review ---
    "185.242.226.0/24"   # Criminal IP
    "69.5.169.0/24"      # InfraWatch
    "45.156.128.0/24"    # Internet Census
    "109.105.210.0/24"   # Internet Census
    "85.217.149.0/24"    # Modat
    "159.223.217.0/24"   # Modat / CyberResilience.io
    "161.35.70.0/24"     # Modat / CyberResilience.io
    "91.196.152.0/24"    # ONYPHE
    "91.230.168.0/24"    # ONYPHE
    "91.231.89.0/24"     # ONYPHE
    "94.231.206.0/24"    # ONYPHE
    "195.184.76.0/24"    # ONYPHE
    "98.80.4.0/24"       # Reposify
    "64.62.156.0/24"     # Shadowserver Foundation
    "64.62.197.0/24"     # Shadowserver Foundation
    "65.49.20.0/24"      # Shadowserver Foundation
    "184.105.247.0/24"   # Shadowserver Foundation
    "71.6.167.0/24"      # Shodan
    "89.248.167.0/24"    # Shodan
    "93.174.95.0/24"     # Shodan
    "20.40.216.0/24"     # Stretchoid
    "20.42.92.0/24"      # Stretchoid
    "20.64.104.0/24"     # Stretchoid
    "20.64.105.0/24"     # Stretchoid
    "20.65.193.0/24"     # Stretchoid
    "20.65.194.0/24"     # Stretchoid
    "20.80.88.0/24"      # Stretchoid
    "20.81.46.0/24"      # Stretchoid
    "20.83.167.0/24"     # Stretchoid
    "20.121.67.0/24"     # Stretchoid
    "20.163.15.0/24"     # Stretchoid
    "20.163.32.0/24"     # Stretchoid
    "20.168.5.0/24"      # Stretchoid
    "20.168.120.0/24"    # Stretchoid
    "20.168.123.0/24"    # Stretchoid
    "20.168.127.0/24"    # Stretchoid
    "20.169.105.0/24"    # Stretchoid
    "20.169.107.0/24"    # Stretchoid
    "20.171.8.0/24"      # Stretchoid
    "20.221.60.0/24"     # Stretchoid
    "40.67.161.0/24"     # Stretchoid
    "40.124.120.0/24"    # Stretchoid
    "40.124.173.0/24"    # Stretchoid
    "40.124.174.0/24"    # Stretchoid
    "40.124.180.0/24"    # Stretchoid
    "40.124.186.0/24"    # Stretchoid
    "52.188.191.0/24"    # Stretchoid
    "57.152.34.0/24"     # Stretchoid
    "135.222.40.0/24"    # Stretchoid
    "135.237.126.0/24"   # Stretchoid
    "172.174.211.0/24"   # Stretchoid
    "172.174.244.0/24"   # Stretchoid
    "172.202.118.0/24"   # Stretchoid
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

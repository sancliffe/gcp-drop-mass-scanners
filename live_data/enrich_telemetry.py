import pandas as pd
import requests
import time
import os

# --- CONFIGURATION ---
INPUT_FILE = 'fail2ban_ip_summary_with_asn_and_rdns.csv'
OUTPUT_FILE = 'fail2ban_ip_summary_enriched.csv'

# SECURITY: Fetch API key from environment to maintain airgap from source control
API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

def calculate_velocity(row):
    """Calculates the attack velocity in connection attempts per hour."""
    try:
        first = pd.to_datetime(row['First Seen'])
        last = pd.to_datetime(row['Last Seen'])
        duration_seconds = (last - first).total_seconds()
        
        attempts = row['Connection Attempts']
        
        # If the attack happened in a single second, treat it as an instant burst
        if duration_seconds <= 1:
            return float(attempts)
        
        duration_hours = duration_seconds / 3600.0
        return round(attempts / duration_hours, 2)
    except Exception:
        return 0.0

def check_abuseipdb(ip):
    """Queries the AbuseIPDB API for the IP's 30-day abuse confidence score."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '30'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data['data']['abuseConfidenceScore']
        elif response.status_code == 429:
            return "Rate Limited"
        else:
            return f"API Error: {response.status_code}"
    except requests.exceptions.RequestException:
        return "Connection Failed"

def main():
    if not API_KEY:
        print("CRITICAL: ABUSEIPDB_API_KEY environment variable is missing.")
        print("Run 'export ABUSEIPDB_API_KEY=\"your_key_here\"' before executing.")
        return

    print(f"Loading telemetry from {INPUT_FILE}...")
    try:
        df = pd.read_csv(INPUT_FILE)
    except FileNotFoundError:
        print(f"Error: Could not find {INPUT_FILE} in the current directory.")
        return
    
    print("Calculating attack velocity (Attempts/Hour)...")
    df['Velocity (Attempts/Hour)'] = df.apply(calculate_velocity, axis=1)
    
    print(f"Querying AbuseIPDB for {len(df)} nodes. Pacing requests to respect API limits...")
    scores = []
    
    for index, ip in enumerate(df['IP Address']):
        print(f"[{index + 1}/{len(df)}] Fetching global reputation for {ip}...")
        score = check_abuseipdb(ip)
        scores.append(score)
        
        # 200ms delay to safely stay under free-tier API throttling limits
        time.sleep(0.2)
        
    df['AbuseIPDB Confidence Score (%)'] = scores
    
    # Sort the final dataset to bubble the most aggressive, highest-threat nodes to the top
    df = df.sort_values(by=['AbuseIPDB Confidence Score (%)', 'Velocity (Attempts/Hour)'], ascending=[False, False])
    
    print(f"\nWriting finalized threat intelligence feed to {OUTPUT_FILE}...")
    df.to_csv(OUTPUT_FILE, index=False)
    print("Execution complete. Perimeter data enriched.")

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Looks up PTR record, ASN, owner, and (optionally) AbuseIPDB reputation
data for each IP/CIDR range.
Outputs results to CSV incrementally (row-by-row).

Dependencies:
    pip install ipwhois dnspython requests

AbuseIPDB usage:
    Pass an API key via --api-key, or set the ABUSEIPDB_API_KEY
    environment variable. If neither is provided, AbuseIPDB columns
    are skipped and the script behaves as before.
    Get a free key at: https://www.abuseipdb.com/account/api
"""

import csv
import sys
import time
import os
import argparse
import ipaddress
import dns.resolver
import dns.reversename
import requests
from pathlib import Path
from ipwhois import IPWhois

# AbuseIPDB's "check" endpoint - returns abuse reports/score for a single IP.
# Docs: https://docs.abuseipdb.com/#check-endpoint
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def get_ptr(ip):
    """
    Resolve the reverse-DNS (PTR) record for a single IP address.

    Uses a short custom resolver timeout so one slow/unresponsive DNS
    server doesn't stall the whole batch - default resolver timeouts
    can be much longer.

    Returns "(no PTR)" on any failure (NXDOMAIN, timeout, malformed
    response, etc). The bare except is intentional here: PTR lookups
    fail for many mundane reasons and none of them should crash the run.
    """
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2   # seconds to wait per DNS server
        resolver.lifetime = 2  # seconds to wait across all retries
        answer = resolver.resolve(rev_name, "PTR")
        # An IP can have multiple PTR records - join them so nothing is lost
        return "; ".join(str(r).rstrip(".") for r in answer)
    except:
        return "(no PTR)"

def get_asn_owner(ip):
    """
    Look up ASN, ASN description, and network/owner name via RDAP.

    RDAP (via ipwhois) is the modern replacement for legacy WHOIS and
    returns structured data instead of free-text, which is why it's
    used here instead of parsing raw WHOIS output.

    Returns "N/A"/"Lookup Failed" placeholders on error so a single bad
    lookup doesn't stop the batch or produce a malformed CSV row.
    """
    try:
        obj = IPWhois(ip)
        # depth=1 follows one level of RDAP referrals (e.g. from the
        # regional registry to the more specific allocation record)
        res = obj.lookup_rdap(depth=1)
        asn = res.get("asn", "N/A")
        asn_desc = res.get("asn_description", "N/A")
        owner = res.get("network", {}).get("name", "N/A")
        return asn, asn_desc, owner
    except:
        return "N/A", "N/A", "Lookup Failed"

def get_abuseipdb_info(ip, api_key, max_age_days=90):
    """
    Query AbuseIPDB's /check endpoint for reputation data on a single IP.

    Args:
        ip: The IP address to check (AbuseIPDB does not accept CIDRs,
            so callers must pass a single address).
        api_key: AbuseIPDB API key (see --api-key / ABUSEIPDB_API_KEY).
        max_age_days: Only count abuse reports within this many days.

    Returns a 5-tuple of (score, reports, last_reported, usage_type,
    domain). On a rate limit (HTTP 429) or any request-level failure
    (timeout, connection error, non-2xx status), returns placeholder
    values instead of raising, so one failed IP doesn't kill the run.
    """
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=5)

        if resp.status_code == 429:
            return "N/A", "N/A", "N/A", "N/A", "Rate Limited"
        resp.raise_for_status()

        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", "N/A")   # 0-100, higher = more likely malicious
        reports = data.get("totalReports", "N/A")
        last_reported = data.get("lastReportedAt") or "Never"
        usage_type = data.get("usageType") or "N/A"        # e.g. "Data Center/Web Hosting/Transit"
        domain = data.get("domain") or "N/A"                # domain associated with the IP, if any
        return score, reports, last_reported, usage_type, domain

    except requests.exceptions.RequestException:
        return "N/A", "N/A", "N/A", "N/A", "Lookup Failed"

def main():
    # --- CLI argument definitions ---
    parser = argparse.ArgumentParser(
        description="Enrich a list of IPs/CIDRs with PTR, ASN, owner, and AbuseIPDB data."
    )
    parser.add_argument(
        "filename", nargs="?", default="blacklist-scanners.txt",
        help="Path to input file (one IP/CIDR per line). Default: blacklist-scanners.txt"
    )
    parser.add_argument(
        "--api-key", dest="api_key", default=None,
        help="AbuseIPDB API key. Falls back to ABUSEIPDB_API_KEY env var if omitted. "
             "If neither is set, AbuseIPDB columns are skipped."
    )
    parser.add_argument(
        "--max-age-days", type=int, default=90,
        help="How far back AbuseIPDB should look for reports (default: 90)."
    )
    args = parser.parse_args()

    filename = args.filename
    # --api-key takes priority over the env var so a one-off flag can
    # override a key that's set globally in the shell environment.
    api_key = args.api_key or os.environ.get("ABUSEIPDB_API_KEY")
    use_abuseipdb = bool(api_key)

    # Output file mirrors the input filename with "_enriched" appended
    # before the extension, e.g. "scanners.txt" -> "scanners_enriched.csv"
    # (preserves whatever directory the input file lives in).
    in_path = Path(filename)
    outfile = str(in_path.with_name(f"{in_path.stem}_enriched.csv"))

    print(f"Reading from {filename}...")
    print(f"Writing results incrementally to {outfile}...")
    if use_abuseipdb:
        print("AbuseIPDB lookups: enabled")
    else:
        print("AbuseIPDB lookups: skipped (no API key provided via --api-key or ABUSEIPDB_API_KEY)")

    try:
        with open(filename, 'r') as f:
            # Strip blank lines up front so line numbers in progress
            # output ([i/total]) match what's actually processed.
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        sys.exit(f"Error: {filename} not found.")

    # Open the output file once and write row-by-row as results come in
    # (rather than building a list and writing at the end) so partial
    # results survive if the script is interrupted or crashes partway
    # through a long run.
    with open(outfile, 'w', newline='') as f:
        fieldnames = ["Entry", "Sample_IP", "PTR", "ASN", "ASN_Desc", "Owner"]
        # Only add AbuseIPDB columns when we actually have a key -
        # keeps the CSV schema identical to the pre-AbuseIPDB version
        # when the feature isn't in use.
        if use_abuseipdb:
            fieldnames += ["Abuse_Score", "Abuse_Reports", "Abuse_Last_Reported", "Usage_Type", "Abuse_Domain"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        total = len(lines)
        for i, line in enumerate(lines, 1):
            try:
                # Accepts both single IPs and CIDR ranges. strict=False
                # allows host bits to be set (e.g. "10.0.0.5/24") instead
                # of requiring a clean network address.
                net = ipaddress.ip_network(line, strict=False)
                # For a CIDR range we only look up the first address in
                # the block as a representative sample - PTR/ASN/owner
                # data is normally the same across a whole allocation,
                # and checking every host would be far too slow/costly.
                sample_ip = str(net.network_address)
                
                print(f"[{i}/{total}] Processing {line}...")
                
                ptr = get_ptr(sample_ip)
                asn, asn_desc, owner = get_asn_owner(sample_ip)

                row = {
                    "Entry": line,
                    "Sample_IP": sample_ip,
                    "PTR": ptr,
                    "ASN": asn,
                    "ASN_Desc": asn_desc,
                    "Owner": owner
                }

                if use_abuseipdb:
                    score, reports, last_reported, usage_type, domain = get_abuseipdb_info(
                        sample_ip, api_key, args.max_age_days
                    )
                    row.update({
                        "Abuse_Score": score,
                        "Abuse_Reports": reports,
                        "Abuse_Last_Reported": last_reported,
                        "Usage_Type": usage_type,
                        "Abuse_Domain": domain
                    })

                # Write this row right away, rather than batching, so
                # results are visible/usable even if a later row fails.
                writer.writerow(row)
                # Force the write out of Python's buffer and onto disk
                # immediately - without this, output.flush() alone
                # wouldn't guarantee the CSV is up to date if the
                # process is killed mid-run.
                f.flush()
                
                # Be a polite API citizen: throttle requests so we don't
                # hammer DNS/RDAP/AbuseIPDB. 0.5s/IP keeps us well under
                # AbuseIPDB's free-tier limit of 1000 checks/day even on
                # large input files.
                time.sleep(0.5)
                
            except ValueError:
                # ip_network() raises ValueError for anything that isn't
                # a valid IP or CIDR (e.g. comments, blank/malformed
                # lines that slipped through) - skip and keep going.
                print(f"[{i}/{total}] Skipping invalid entry: {line}")

    print(f"\nProcessing complete. Incremental file {outfile} is ready.")

if __name__ == "__main__":
    main()

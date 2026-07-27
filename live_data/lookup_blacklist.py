#!/usr/bin/env python3
"""
Looks up PTR record, ASN, and owner (org) for each IP/CIDR range in the provided text file.

Dependencies:
    pip install ipwhois dnspython
"""

import csv
import sys
import time
import ipaddress
import dns.resolver
import dns.reversename
from ipwhois import IPWhois

def get_ptr(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answer = resolver.resolve(rev_name, "PTR")
        return "; ".join(str(r).rstrip(".") for r in answer)
    except:
        return "(no PTR)"

def get_asn_owner(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        asn = res.get("asn", "N/A")
        asn_desc = res.get("asn_description", "N/A")
        owner = res.get("network", {}).get("name", "N/A")
        return asn, asn_desc, owner
    except:
        return "N/A", "N/A", "Lookup Failed"

def main():
    # Use the filename provided as the first argument, or default to stdin/hardcoded list
    filename = sys.argv[1] if len(sys.argv) > 1 else "blacklist-scanners.txt"
    outfile = "blacklist_enriched.csv"

    print(f"Reading from {filename}...")
    
    try:
        with open(filename, 'r') as f:
            # We strip whitespace and ignore empty lines
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        sys.exit(f"Error: {filename} not found.")

    rows = []
    total = len(lines)

    for i, line in enumerate(lines, 1):
        try:
            # Force IPv4 network object creation.
            # strict=False allows treating "192.168.1.1/24" as a network 192.168.1.0/24
            net = ipaddress.ip_network(line, strict=False)
            sample_ip = str(net.network_address)
            
            print(f"[{i}/{total}] Processing {line} (Sample: {sample_ip})...")
            
            ptr = get_ptr(sample_ip)
            asn, asn_desc, owner = get_asn_owner(sample_ip)
            
            rows.append({
                "Entry": line,
                "Sample_IP": sample_ip,
                "PTR": ptr,
                "ASN": asn,
                "ASN_Desc": asn_desc,
                "Owner": owner
            })
            
            # Rate limiting to prevent IP blacklisting from the look-up providers
            time.sleep(0.5)
            
        except ValueError:
            print(f"[{i}/{total}] Skipping invalid entry: {line}")

    with open(outfile, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["Entry", "Sample_IP", "PTR", "ASN", "ASN_Desc", "Owner"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nProcessing complete. Results saved to {outfile}")

if __name__ == "__main__":
    main()

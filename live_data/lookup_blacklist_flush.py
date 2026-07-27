#!/usr/bin/env python3
"""
Looks up PTR record, ASN, and owner for each IP/CIDR range.
Outputs results to CSV incrementally (row-by-row).

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
    filename = sys.argv[1] if len(sys.argv) > 1 else "blacklist-scanners.txt"
    outfile = "blacklist_enriched.csv"
    
    print(f"Reading from {filename}...")
    print(f"Writing results incrementally to {outfile}...")

    try:
        with open(filename, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        sys.exit(f"Error: {filename} not found.")

    # Open file for writing and initialize CSV writer
    with open(outfile, 'w', newline='') as f:
        fieldnames = ["Entry", "Sample_IP", "PTR", "ASN", "ASN_Desc", "Owner"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        total = len(lines)
        for i, line in enumerate(lines, 1):
            try:
                net = ipaddress.ip_network(line, strict=False)
                sample_ip = str(net.network_address)
                
                print(f"[{i}/{total}] Processing {line}...")
                
                ptr = get_ptr(sample_ip)
                asn, asn_desc, owner = get_asn_owner(sample_ip)
                
                # Write individual row immediately
                writer.writerow({
                    "Entry": line,
                    "Sample_IP": sample_ip,
                    "PTR": ptr,
                    "ASN": asn,
                    "ASN_Desc": asn_desc,
                    "Owner": owner
                })
                # Flush the file buffer to ensure it's written to disk
                f.flush()
                
                # Rate limiting
                time.sleep(0.5)
                
            except ValueError:
                print(f"[{i}/{total}] Skipping invalid entry: {line}")

    print(f"\nProcessing complete. Incremental file {outfile} is ready.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Looks up PTR record, ASN, and owner (org) for each IP/CIDR range in blacklist.txt.

Install dependencies first:
    pip install ipwhois dnspython

Usage:
    python lookup_blacklist.py blacklist.txt output.csv

Notes:
- PTR records only make sense for a single IP, not a whole /24 or /16 range.
  For each range, this script queries PTR on the *network address* (first IP)
  of the block as a representative sample. If you want PTR for every single
  IP in a /16, that's 65,536 DNS queries per range -- not something you want
  to do for 80 ranges. Adjust SAMPLE_MODE below if you need per-host PTRs for
  smaller ranges.
- ASN/owner data comes from RDAP (via ipwhois), which queries the regional
  internet registries (ARIN, RIPE, APNIC, etc.) directly.
- This will make ~80-160 network calls total and may take a few minutes.
  Some ranges (especially large ISPs) may rate-limit; the script retries once.
"""

import csv
import sys
import time
import ipaddress

try:
    import dns.resolver
    import dns.reversename
except ImportError:
    sys.exit("Missing dependency: run `pip install dnspython --break-system-packages`")

try:
    from ipwhois import IPWhois
except ImportError:
    sys.exit("Missing dependency: run `pip install ipwhois --break-system-packages`")


def get_ptr(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answer = resolver.resolve(rev_name, "PTR")
        return "; ".join(str(r).rstrip(".") for r in answer)
    except Exception as e:
        return f"(no PTR / {type(e).__name__})"


def get_asn_owner(ip, retries=1):
    for attempt in range(retries + 1):
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            asn = res.get("asn", "")
            asn_desc = res.get("asn_description", "")
            network = res.get("network", {}) or {}
            owner = network.get("name", "") or asn_desc
            return asn, asn_desc, owner
        except Exception as e:
            if attempt < retries:
                time.sleep(1)
                continue
            return "N/A", "N/A", f"(lookup failed: {type(e).__name__})"


def main():
    infile = sys.argv[1] if len(sys.argv) > 1 else "blacklist.txt"
    outfile = sys.argv[2] if len(sys.argv) > 2 else "blacklist_lookup.csv"

    with open(infile) as f:
        entries = [line.strip() for line in f if line.strip()]

    rows = []
    for i, entry in enumerate(entries, 1):
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            print(f"[{i}/{len(entries)}] SKIP invalid entry: {entry}")
            continue

        sample_ip = str(net.network_address)
        print(f"[{i}/{len(entries)}] {entry} -> sampling {sample_ip}")

        ptr = get_ptr(sample_ip)
        asn, asn_desc, owner = get_asn_owner(sample_ip)

        rows.append({
            "CIDR/IP": entry,
            "Sample IP": sample_ip,
            "PTR Record": ptr,
            "ASN": asn,
            "ASN Description": asn_desc,
            "Owner": owner,
        })
        time.sleep(0.3)  # be polite to RDAP/DNS servers

    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDone. Wrote {len(rows)} rows to {outfile}")


if __name__ == "__main__":
    main()

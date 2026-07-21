# gcp-drop-mass-scanners

A lightweight, automated toolkit for blocking traffic from known internet mass scanners, indexers, and abusive hosting ranges — such as Shodan, Censys, Stretchoid, ONYPHE, Palo Alto Cortex Xpanse, and others — from reaching your Google Cloud Platform (GCP) infrastructure.

The repo ships several standalone shell scripts, each of which creates or updates a **GCP VPC firewall rule** that denies **all ingress traffic** from a curated list of IP ranges. It also includes Python scripts for analyzing log data to identify new ranges to block.

| Script                | Firewall rule name           | Priority | Target                                                                                                |
| --------------------- | ----------------------------- | -------- | ----------------------------------------------------------------------------------------------------- |
| `block_attacks.sh`    | `network-drop-attackers`      | `10`     | General abusive IPs/ranges sourced from a local blacklist file (`blacklist-attackers.txt`)            |
| `block_scanners.sh`   | `network-drop-mass-scanners`  | `11`     | General internet scanners, indexers, and research crawlers (Shodan, Censys, Stretchoid, ONYPHE, etc.) |
| `block_vdsina.sh`     | `network-drop-vdsina`         | `11`     | VDSina / Unmanaged LTD hosting ranges observed in Fail2Ban logs                                       |
| `block_omegatech.sh`  | `network-drop-omegatech`      | `12`     | Omegatech LTD (AS202412) hosting ranges                                                               |
| `block_hydracomms.sh` | `network-drop-hydracomms`     | `12`     | Hydra Communications (AS25369) — hardcoded in-script                                                  |
| `block_lordvps.sh`    | `network-drop-lordvps`        | `12`     | LORDVPS (AS209425) — hardcoded in-script                                                              |

## How it works

Each shell script follows a similar pattern:

1.  It gathers a list of IP/CIDR ranges.
    -   Scripts like `block_vdsina.sh` use a hardcoded `TARGET_RANGES` array inside the script.
    -   Scripts like `block_scanners.sh` and `block_attacks.sh` read from an external text file (`blacklist-scanners.txt` and `blacklist-attackers.txt`, respectively), allowing for easier updates without modifying the script itself.
2.  It joins these ranges into a single comma-separated string.
3.  It checks whether its corresponding firewall rule already exists in the target GCP project.
4.  **If the rule exists**, it updates the rule's `--source-ranges` to match the current list.
5.  **If the rule does not exist**, it creates a new `DENY` ingress rule with:
  - `--action=DENY`
  - `--rules=all`
  - `--direction=INGRESS`
  - the priority listed in the table above
  - the configured source ranges

This makes each script idempotent — safe to re-run any time you add or remove ranges, without needing to manually delete and recreate the rule.

## Scripts

### `block_attacks.sh`

Blocks IP ranges sourced from the `blacklist-attackers.txt` file. This script is intended for a general-purpose, manually curated blocklist of IPs observed engaging in hostile activity.

### `block_scanners.sh`

Blocks known scanner and indexer infrastructure by reading ranges from `blacklist-scanners.txt`. The list includes providers such as:

- Censys, Shodan, ONYPHE, Modat, Criminal IP, Reposify — research/indexing scanners
- Palo Alto Cortex Xpanse, Shadowserver Foundation, InfraWatch, Internet Census — security research scanners
- Stretchoid — a large block of Microsoft Azure–hosted ranges tied to persistent unsolicited scanning
- Hurricane Electric, DigitalOcean, CariNet, VisionHeight, Nokia Deepfield — hosting ranges observed scanning directly

> This list is maintained in the `blacklist-scanners.txt` file and grows over time as new scanners are identified from log review. Check that file for the authoritative, up-to-date list.

### `block_vdsina.sh`

Blocks ranges associated with **VDSina / Unmanaged LTD** (Russian Federation hosting), including a specific `/24` captured directly from Fail2Ban logs and the two known upstream `AS48282` / `AS216071` blocks.

> **Note:** this script currently ships with `PROJECT_ID` hardcoded to a specific project. If you fork or reuse this script, replace it with your own project ID (or blank it out, as the other scripts do) before committing changes back.

### `block_omegatech.sh`

Blocks a single `/21` range belonging to **Omegatech LTD (AS202412)**, identified as a source of malicious traffic.

### `block_hydracomms.sh`

Blocks the largest announced prefixes belonging to **Hydra Communications (AS25369)** — 10 `/20`–`/21` ranges hardcoded in-script. AS25369 announces 200+ prefixes total; GCP caps a single firewall rule at 256 source ranges, so only the largest blocks are included.

### `block_lordvps.sh`

Blocks `81.30.98.0/24`, a range belonging to **LORDVPS (AS209425)**. RIPE allocation `IR-LORDVPS11-20240618`, registered to "Atis Omran Sevin PSJ" (Tehran, IR), with a generic Gmail abuse contact rather than a corporate abuse desk. Identified from `postfix`/`postscreen` PREGREET failures — bots across ~8 IPs in the range sending `EHLO` before the server's SMTP greeting, a common signature of spam-bot software rather than legitimate mail clients. Also listed on AbuseIPDB. This is a newly created (2024) block on a low-reputation VPS host, so an outright `/24` block is low-risk.

### Data Analysis & Research Scripts

The `/live_data` directory contains Python scripts used for research and analysis to identify new threats. These scripts are not run as part of the deployment but are used to process log data and enrich it with external threat intelligence.

#### `lookup_blacklist.py`

This script takes a list of IPs/CIDRs (like `blacklist-attackers.txt`) and enriches it by looking up the PTR record, ASN, and owner for each entry. This helps in identifying the source and nature of the traffic.

#### `enrich_telemetry.py`

This script processes a CSV of observed IPs (e.g., from Fail2Ban logs), calculates attack velocity, and queries the AbuseIPDB API to get a "confidence score" for how malicious an IP is reputed to be. The output helps prioritize which IPs or ranges are candidates for blocking.

> These scripts help turn raw log data into actionable intelligence, which can then be used to update the `TARGET_RANGES` in the shell scripts or the contents of the `blacklist-*.txt` files.

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated (`gcloud auth login`)
- Sufficient IAM permissions on the target project to create/update firewall rules (e.g. `roles/compute.securityAdmin` or equivalent)
- A GCP project with a VPC network (default network name assumed unless configured otherwise)
- Python 3 with `pandas` and `requests` installed, plus an [AbuseIPDB](https://www.abuseipdb.com/) API key — only required if you want to run `live_data/enrich_telemetry.py`

## Configuration

Before running any script, edit its configuration block at the top:

```
PROJECT_ID=""          # Your GCP project ID (required)
NETWORK_NAME="default" # The VPC network the rule should apply to
RULE_NAME="..."        # Pre-set per script; change only if you want a different rule name
```

`PROJECT_ID` must be set (or already set, in the case of `block_vdsina.sh` — see the note above) — none of the scripts prompt for it, and each will fail against `gcloud` if left blank or incorrect.

## Usage

Run whichever script(s) match the traffic you want to block:

```bash
chmod +x *.sh

./block_attacks.sh
./block_scanners.sh
./block_vdsina.sh
./block_omegatech.sh
./block_hydracomms.sh
./block_lordvps.sh
```

Each script prints output confirming whether its rule was created or updated, ending with a completion message (e.g. `Deployment complete.`).

## Updating the block lists

**`block_scanners.sh`** — edit `blacklist.txt` directly, one CIDR per line (inline `#` comments are stripped automatically), then re-run the script:

```
184.105.136.0/22
203.0.113.0/24   # New range you're adding
```

**`block_vdsina.sh` / `block_omegatech.sh`** — edit the `TARGET_RANGES` array in the relevant script and re-run it:

```
TARGET_RANGES=(
    "62.113.112.0/20"  # Known VDSina AS48282 primary block
    "203.0.113.0/24"   # New range you're adding
)
```

Since each rule is checked for existence first, re-running any script simply updates `--source-ranges` on the existing rule rather than duplicating it.

If you're working from the `live_data/` CSVs, look for IPs with a high `Connection Attempts`, `Velocity (Attempts/Hour)`, or `AbuseIPDB Confidence Score (%)`, confirm the owning ASN, and add the CIDR to the appropriate file.

## Automating this

Because the scripts are idempotent, they're good candidates for scheduling (e.g. via `cron`, a CI pipeline, or Cloud Scheduler + Cloud Run/Functions) if you want to keep firewall rules in sync with an external or periodically updated scanner IP feed.

## Notes & caveats

- All scripts use `set -e`, so they'll exit immediately on any `gcloud` error (e.g. bad project ID, insufficient permissions).
- Each rule denies **all protocols/ports** (`--rules=all`) from its listed ranges — this is a blanket edge block, not a targeted port rule.
- `block_omegatech.sh`, `block_hydracomms.sh`, and `block_lordvps.sh` share priority `12` since each targets a distinct, non-overlapping range — collisions aren't a concern, but keep this in mind if you rename or consolidate rules.
- IP ranges owned by scanning services and hosting providers can change over time. Periodically verify entries against current provider documentation (e.g. Shodan, Censys, Palo Alto Cortex Xpanse) or WHOIS/ASN lookups rather than assuming these lists stay accurate indefinitely.
- `block_vdsina.sh` ships with a project ID already filled in — review before running against your own environment, and avoid committing real project IDs, IPs, API keys, or logs you don't want public if you extend this repo.
- Never commit your `ABUSEIPDB_API_KEY` — `enrich_telemetry.py` expects it as an environment variable for this reason.

## License

This project is licensed under the MIT License — see the LICENSE file for details.

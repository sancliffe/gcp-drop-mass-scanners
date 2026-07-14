# gcp-drop-mass-scanners

A lightweight, automated toolkit for blocking traffic from known internet mass scanners, indexers, and abusive hosting ranges — such as Shodan, Censys, Stretchoid, ONYPHE, Palo Alto Cortex Xpanse, and others — from reaching your Google Cloud Platform (GCP) infrastructure.

The repo ships three standalone scripts, each of which creates or updates a **GCP VPC firewall rule** that denies **all ingress traffic** from a curated list of IP ranges, plus a `live_data/` folder of Fail2Ban telemetry used to identify new ranges to block.

| Script | Firewall rule name | Priority | Target |
|---|---|---|---|
| `block_scanners.sh` | `network-drop-mass-scanners` | `10` | General internet scanners, indexers, and research crawlers (Shodan, Censys, Stretchoid, ONYPHE, etc.) |
| `block_vdsina.sh` | `network-drop-vdsina` | `11` | VDSina / Unmanaged LTD hosting ranges observed in Fail2Ban logs |
| `block_omegatech.sh` | `network-drop-omegatech` | `12` | Omegatech LTD (AS202412) hosting ranges |
| `block_hydracomms.sh` | `network-drop-hydracomms` | `12` | Hardcoded in-script | Hydra Communications (AS25369) hosting ranges |

## How it works

All three scripts share the same deployment pattern:

1. Assemble a comma-separated list of CIDR ranges to block (from `blacklist.txt` for `block_scanners.sh`, or from a hardcoded `TARGET_RANGES` array for the other two).
2. Check whether the script's firewall rule already exists in the target GCP project.
3. **If the rule exists**, update its `--source-ranges` to match the current list.
4. **If the rule does not exist**, create a new `DENY` ingress rule with:
   - `--action=DENY`
   - `--rules=all`
   - `--direction=INGRESS`
   - the priority listed in the table above
   - the configured source ranges

This makes each script idempotent — safe to re-run any time you add or remove ranges, without needing to manually delete and recreate the rule.

## Scripts

### `block_scanners.sh`

Blocks known scanner and indexer infrastructure. Reads its ranges from `blacklist.txt` (currently 70+ CIDR ranges) rather than a hardcoded list, so updating the blocklist is just a file edit — no script changes needed. Providers currently represented include:

- Censys, Shodan, ONYPHE, Modat, Criminal IP, Reposify — research/indexing scanners
- Palo Alto Cortex Xpanse, Shadowserver Foundation, InfraWatch, Internet Census — security research scanners
- Stretchoid — a large block of Microsoft Azure–hosted ranges tied to persistent unsolicited scanning
- Hurricane Electric, DigitalOcean, CariNet, VisionHeight, Nokia Deepfield — hosting ranges observed scanning directly

The script also:

- Supports a `--dry-run` flag that prints the assembled `--source-ranges` string without touching GCP, so you can sanity-check a `blacklist.txt` edit before deploying it.
- Warns (but does not block) if the assembled source-ranges string exceeds `MAX_CHARS` (7000 characters by default) — GCP firewall rules have a hard character limit on `--source-ranges`, so this flags when it's time to consider migrating to a [Network Firewall Policy](https://cloud.google.com/firewall/docs/firewall-policies-overview) instead.
- Deploys the rule with `--enable-logging`, so blocked traffic shows up in Cloud Logging.

> `blacklist.txt` is the authoritative, up-to-date list — check it directly rather than relying on the summary above.

### `block_vdsina.sh`

Blocks ranges associated with **VDSina / Unmanaged LTD** (Russian Federation hosting), including a specific `/24` captured directly from Fail2Ban logs and the two known upstream `AS48282` / `AS216071` blocks.

> **Note:** this script currently ships with `PROJECT_ID` hardcoded to a specific project. If you fork or reuse this script, replace it with your own project ID (or blank it out, as `block_omegatech.sh` does) before committing changes back.

### `block_omegatech.sh`

Blocks a single `/21` range belonging to **Omegatech LTD (AS202412)**, identified as a source of malicious traffic.

### `live_data/`

Raw and enriched Fail2Ban telemetry used as the research basis for new blocklist entries — not consumed directly by any of the block scripts.

| File | Description |
|---|---|
| `fail2ban_ip_summary_with_asn_and_rdns.csv` | Base export of individual IPs observed hitting `sshd`, `postfix`, `dovecot`, and other jails, with columns: `IP Address, First Seen, Last Seen, Reason(s) / Jail(s), Connection Attempts, Times Banned, ASN & Owner, Reverse DNS (PTR)` |
| `fail2ban_ip_summary_enriched.csv` | Output of `enrich_telemetry.py` — the same data with two additional columns: `Velocity (Attempts/Hour)` and `AbuseIPDB Confidence Score (%)`, sorted with the highest-confidence, highest-velocity offenders first |
| `enrich_telemetry.py` | Python script that reads the base CSV, computes attack velocity per IP, queries the [AbuseIPDB](https://www.abuseipdb.com/) API for a 30-day abuse confidence score per IP, and writes the enriched CSV |

To run the enrichment script:

```bash
pip install pandas requests
export ABUSEIPDB_API_KEY="your_key_here"
cd live_data
python3 enrich_telemetry.py
```

The script reads `ABUSEIPDB_API_KEY` from the environment (never hardcode it) and paces requests with a 200ms delay between calls to stay under AbuseIPDB's free-tier rate limit.

Look for IPs in the enriched CSV with a high `AbuseIPDB Confidence Score (%)` and `Velocity (Attempts/Hour)`, confirm the owning ASN, and add the CIDR to `blacklist.txt` (for general scanners) or the appropriate `TARGET_RANGES` array (for provider-specific scripts).

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated (`gcloud auth login`)
- Sufficient IAM permissions on the target project to create/update firewall rules (e.g. `roles/compute.securityAdmin` or equivalent)
- A GCP project with a VPC network (default network name assumed unless configured otherwise)
- Python 3 with `pandas` and `requests` installed, plus an [AbuseIPDB](https://www.abuseipdb.com/) API key — only required if you want to run `live_data/enrich_telemetry.py`

## Configuration

Before running any script, edit its configuration block at the top:

```bash
PROJECT_ID=""          # Your GCP project ID (required)
NETWORK_NAME="default" # The VPC network the rule should apply to
RULE_NAME="..."        # Pre-set per script; change only if you want a different rule name
```

`PROJECT_ID` must be set (or already set, in the case of `block_vdsina.sh` — see the note above) — none of the scripts prompt for it, and each will fail against `gcloud` if left blank or incorrect.

## Usage

Run whichever script(s) match the traffic you want to block:

```bash
chmod +x block_scanners.sh block_vdsina.sh block_omegatech.sh

./block_scanners.sh --dry-run   # optional: preview the assembled source-ranges first
./block_scanners.sh
./block_vdsina.sh
./block_omegatech.sh
```

Each script prints output confirming whether its rule was created or updated, ending with a completion message (e.g. `Deployment complete.`).

## Updating the block lists

**`block_scanners.sh`** — edit `blacklist.txt` directly, one CIDR per line (inline `#` comments are stripped automatically), then re-run the script:

```
184.105.136.0/22
203.0.113.0/24   # New range you're adding
```

**`block_vdsina.sh` / `block_omegatech.sh`** — edit the `TARGET_RANGES` array in the relevant script and re-run it:

```bash
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

- All three scripts use `set -e`, so they'll exit immediately on any `gcloud` error (e.g. bad project ID, insufficient permissions).
- Each rule denies **all protocols/ports** (`--rules=all`) from its listed ranges — this is a blanket edge block, not a targeted port rule.
- The three rules use adjacent priorities (`10`, `11`, `12`), giving them high precedence over other rules in the VPC — make sure they don't unintentionally conflict with rules you rely on elsewhere.
- `block_scanners.sh` warns once `blacklist.txt` pushes `--source-ranges` past 7000 characters, since GCP firewall rules have a fixed limit on that field's length — plan a migration to a Network Firewall Policy before you hit it.
- IP ranges owned by scanning services and hosting providers can change over time. Periodically verify entries against current provider documentation (e.g. Shodan, Censys, Palo Alto Cortex Xpanse) or WHOIS/ASN lookups rather than assuming these lists stay accurate indefinitely.
- `block_vdsina.sh` ships with a project ID already filled in — review before running against your own environment, and avoid committing real project IDs, IPs, API keys, or logs you don't want public if you extend this repo.
- Never commit your `ABUSEIPDB_API_KEY` — `enrich_telemetry.py` expects it as an environment variable for this reason.

## License

This project is licensed under the MIT License — see the LICENSE file for details.

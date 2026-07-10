# gcp-drop-mass-scanners

A lightweight, automated toolkit for blocking traffic from known internet mass scanners, indexers, and abusive hosting ranges — such as Shodan, Censys, Stretchoid, ONYPHE, Palo Alto Cortex Xpanse, and others — from reaching your Google Cloud Platform (GCP) infrastructure.

The repo ships three standalone scripts, each of which creates or updates a **GCP VPC firewall rule** that denies **all ingress traffic** from a curated list of IP ranges, plus a CSV log of individually observed IPs used to identify new ranges to block.

| Script | Firewall rule name | Priority | Target |
|---|---|---|---|
| `block_scanners.sh` | `network-drop-mass-scanners` | `10` | General internet scanners, indexers, and research crawlers (Shodan, Censys, Stretchoid, ONYPHE, etc.) |
| `block_vdsina.sh` | `network-drop-vdsina` | `11` | VDSina / Unmanaged LTD hosting ranges observed in Fail2Ban logs |
| `block_omegatech.sh` | `network-drop-omegatech` | `12` | Omegatech LTD (AS202412) hosting ranges |

## How it works

Each script follows the same pattern:

1. Joins a hardcoded array of scanner/abuse CIDR ranges (`TARGET_RANGES`) into a single comma-separated string.
2. Checks whether its firewall rule already exists in the target GCP project.
3. **If the rule exists**, it updates the rule's `--source-ranges` to match the current list.
4. **If the rule does not exist**, it creates a new `DENY` ingress rule with:
   - `--action=DENY`
   - `--rules=all`
   - `--direction=INGRESS`
   - the priority listed in the table above
   - the configured source ranges

This makes each script idempotent — safe to re-run any time you add or remove ranges, without needing to manually delete and recreate the rule.

## Scripts

### `block_scanners.sh`

Blocks known scanner and indexer infrastructure. Currently maintains **60+ ranges** across providers including:

- Censys, Shodan, ONYPHE, Modat, Criminal IP, Reposify — research/indexing scanners
- Palo Alto Cortex Xpanse, Shadowserver Foundation, InfraWatch, Internet Census — security research scanners
- Stretchoid — a large block of Microsoft Azure–hosted ranges (the bulk of the list) tied to persistent unsolicited scanning
- Hurricane Electric, DigitalOcean, CariNet, VisionHeight, Nokia Deepfield — hosting ranges observed scanning directly

> This list is maintained by hand inside the script and grows over time as new scanners are identified from log review. Check `block_scanners.sh` for the authoritative, up-to-date list.

### `block_vdsina.sh`

Blocks ranges associated with **VDSina / Unmanaged LTD** (Russian Federation hosting), including a specific `/24` captured directly from Fail2Ban logs and the two known upstream `AS48282` / `AS216071` blocks.

> **Note:** this script currently ships with `PROJECT_ID` hardcoded to a specific project. If you fork or reuse this script, replace it with your own project ID (or blank it out, as the other two scripts do) before committing changes back.

### `block_omegatech.sh`

Blocks a single `/21` range belonging to **Omegatech LTD (AS202412)**, identified as a source of malicious traffic.

### `unique_ips.csv`

A log of individual IPs observed hitting `sshd`, `postfix`, `dovecot`, and other jails via Fail2Ban, with columns:

```
ip_address, first_seen, last_seen, attempt_count, jails, was_banned
```

This file isn't consumed by any script directly — it's the raw research data used to spot patterns (repeat offenders, shared subnets/ASNs) that get promoted into `TARGET_RANGES` entries in the scripts above.

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated (`gcloud auth login`)
- Sufficient IAM permissions on the target project to create/update firewall rules (e.g. `roles/compute.securityAdmin` or equivalent)
- A GCP project with a VPC network (default network name assumed unless configured otherwise)

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

./block_scanners.sh
./block_vdsina.sh
./block_omegatech.sh
```

Each script prints output confirming whether its rule was created or updated, ending with a completion message (e.g. `Firewall infrastructure update complete.`).

## Updating the block lists

To add or remove a range, edit the `TARGET_RANGES` array in the relevant script and re-run it. Since each rule is checked for existence first, re-running simply updates `--source-ranges` on the existing rule rather than duplicating it.

```bash
TARGET_RANGES=(
    "184.105.136.0/22" # Hurricane Electric
    "203.0.113.0/24"   # New range you're adding
)
```

If you're working from `unique_ips.csv`, look for IPs with a high `attempt_count` or repeated entries in the same `/24`, confirm the owning ASN, and add the CIDR to the appropriate script.

## Automating this

Because the scripts are idempotent, they're good candidates for scheduling (e.g. via `cron`, a CI pipeline, or Cloud Scheduler + Cloud Run/Functions) if you want to keep firewall rules in sync with an external or periodically updated scanner IP feed.

## Notes & caveats

- All three scripts use `set -e`, so they'll exit immediately on any `gcloud` error (e.g. bad project ID, insufficient permissions).
- Each rule denies **all protocols/ports** (`--rules=all`) from its listed ranges — this is a blanket edge block, not a targeted port rule.
- The three rules use adjacent priorities (`10`, `11`, `12`), giving them high precedence over other rules in the VPC — make sure they don't unintentionally conflict with rules you rely on elsewhere.
- IP ranges owned by scanning services and hosting providers can change over time. Periodically verify entries against current provider documentation (e.g. Shodan, Censys, Palo Alto Cortex Xpanse) or WHOIS/ASN lookups rather than assuming these lists stay accurate indefinitely.
- `block_vdsina.sh` ships with a project ID already filled in — review before running against your own environment, and avoid committing real project IDs, IPs, or logs you don't want public if you extend this repo.

## License

This project is licensed under the MIT License — see the LICENSE file for details.

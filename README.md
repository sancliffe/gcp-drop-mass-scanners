# gcp-drop-mass-scanners

A lightweight, automated solution for blocking traffic from known internet mass scanners — such as Shodan, Censys, Palo Alto Cortex Xpanse, and others — from reaching your Google Cloud Platform (GCP) infrastructure.

The repo currently ships a single script, `block_scanners.sh`, which creates or updates a GCP VPC firewall rule that denies **all ingress traffic** from a curated list of known scanner/indexer IP ranges.

## How it works

The script:

1. Joins a hardcoded array of scanner CIDR ranges (`TARGET_RANGES`) into a single comma-separated string.
2. Checks whether a firewall rule named `network-drop-mass-scanners` already exists in the target GCP project.
3. **If the rule exists**, it updates the rule's `--source-ranges` to match the current list.
4. **If the rule does not exist**, it creates a new `DENY` ingress rule with:
   - `--action=DENY`
   - `--rules=all`
   - `--direction=INGRESS`
   - `--priority=10`
   - the configured source ranges

This makes the script idempotent — safe to re-run any time you add or remove ranges, without needing to manually delete and recreate the rule.

## Blocked ranges (as of this writing)

| CIDR | Source / Notes |
|---|---|
| `184.105.136.0/22` | Hurricane Electric |
| `141.212.0.0/16` | Censys |
| `162.243.128.0/19` | DigitalOcean |
| `71.6.232.0/24` | CariNet |
| `94.102.49.0/24` | Shodan |
| `65.49.1.0/24` | Shadowserver |
| `35.203.210.0/23` | Palo Alto Cortex Xpanse (expanded to /23 to catch `.211.x`) |
| `18.116.101.0/24` | VisionHeight |
| `94.26.106.0/24` | Persistent scanner block observed July 7th |
| `216.180.246.0/24` | Nokia Deepfield Scanners |

> This list is maintained by hand inside the script. Check `block_scanners.sh` for the authoritative, up-to-date list — this table may lag behind new additions.

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated (`gcloud auth login`)
- Sufficient IAM permissions on the target project to create/update firewall rules (e.g. `roles/compute.securityAdmin` or equivalent)
- A GCP project with a VPC network (default network name assumed unless configured otherwise)

## Configuration

Before running, edit the configuration block at the top of `block_scanners.sh`:

```bash
PROJECT_ID=""          # Your GCP project ID (required)
NETWORK_name="default" # The VPC network the rule should apply to
RULE_NAME="network-drop-mass-scanners"
```

`PROJECT_ID` must be set — the script does not prompt for it and will fail against `gcloud` if left blank.

## Usage

```bash
chmod +x block_scanners.sh
./block_scanners.sh
```

On success you'll see output confirming whether the rule was created or updated, followed by:

```
Firewall infrastructure update complete.
```

## Updating the block list

To add or remove a range, edit the `TARGET_RANGES` array in `block_scanners.sh` and re-run the script. Since the rule is checked for existence first, re-running simply updates `--source-ranges` on the existing rule rather than duplicating it.

```bash
TARGET_RANGES=(
    "184.105.136.0/22" # Hurricane Electric
    "203.0.113.0/24"   # New range you're adding
)
```

## Automating this

Because the script is idempotent, it's a good candidate for scheduling (e.g. via `cron`, a CI pipeline, or Cloud Scheduler + Cloud Run/Functions) if you want to keep firewall rules in sync with an external or periodically updated scanner IP feed.

## Notes & caveats

- The script uses `set -e`, so it will exit immediately on any `gcloud` error (e.g. bad project ID, insufficient permissions).
- The rule denies **all protocols/ports** (`--rules=all`) from the listed ranges — it's a blanket edge block, not a targeted port rule.
- `--priority=10` gives this rule high precedence; make sure it doesn't unintentionally conflict with other firewall rules in your VPC.
- IP ranges owned by scanning services can change over time. Periodically verify entries against current provider documentation (e.g. Shodan, Censys, Palo Alto Cortex Xpanse) rather than assuming this list stays accurate indefinitely.

## License

Add your preferred license here (e.g. MIT).

# gcp-drop-mass-scanners

A lightweight, automated solution for blocking traffic from known internet mass scanners — such as **Shodan**, **Censys**, **Palo Alto Expanse**, **LeakIX**, and others — from reaching your Google Cloud Platform (GCP) infrastructure.

By proactively dropping this traffic at the edge using **Google Cloud Armor** and/or **VPC Firewall Rules**, this project helps you:

- 🔇 **Reduce log noise** from opportunistic, non-malicious reconnaissance scanning
- 💸 **Save on bandwidth / egress costs** associated with responding to scanner probes
- 🕵️ **Reduce the visibility** of your infrastructure to mass internet-wide scanning services
- 🛡️ **Lower your attack surface** by cutting down the reconnaissance data available to attackers who rely on these platforms

## How It Works

Mass internet scanning services continuously sweep the entire IPv4 (and increasingly IPv6) address space and publish their findings, often making them searchable by anyone. Many of these services publish the IP ranges they scan from.

This repository maintains and applies rules that:

1. Pull in known IP ranges/addresses associated with mass scanning services
2. Convert them into GCP-compatible firewall rule / Cloud Armor security policy definitions
3. Apply those rules to your GCP project so matching traffic is dropped before it reaches your workloads

## Prerequisites

- A Google Cloud Platform project with billing enabled
- `gcloud` CLI installed and authenticated ([install guide](https://cloud.google.com/sdk/docs/install))
- Sufficient IAM permissions to manage firewall rules and/or Cloud Armor security policies (e.g. `roles/compute.securityAdmin`)
- [Terraform](https://developer.hashicorp.com/terraform/install) (if using the Terraform deployment path)

## Installation

Clone the repository:

```bash
git clone https://github.com/sancliffe/gcp-drop-mass-scanners.git
cd gcp-drop-mass-scanners
```

Authenticate with GCP and set your target project:

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

Review and apply the rules using your preferred deployment method (Terraform or `gcloud`/scripts), following the instructions in this repository.

## Configuration

Adjust the source IP lists and target scope to fit your environment before applying:

| Setting | Description |
|---|---|
| Scanner sources | Which mass-scanner services' IP ranges to block (Shodan, Censys, Expanse, LeakIX, etc.) |
| Enforcement mode | Cloud Armor security policy vs. VPC firewall rule |
| Scope | Global (Cloud Armor / load balancer) vs. per-VPC/network (firewall rules) |
| Logging | Enable/disable logging on dropped traffic for auditing |

## Keeping IP Lists Up to Date

Mass scanner IP ranges change over time. It's recommended to periodically refresh the source IP lists and re-apply the rules (e.g. via a scheduled CI job or Cloud Scheduler + Cloud Function) to ensure blocking remains effective.

## Disclaimer

This project blocks traffic from *known, published* scanner ranges. It is not a substitute for a complete security strategy and does not protect against targeted attacks, scanners using unlisted/rotating IPs, or scanners that intentionally evade published ranges. Always test rule changes in a non-production environment before rolling out broadly, as overly broad rules can inadvertently block legitimate traffic.


# Sentinel

**A modular, defensive security toolkit.** Sentinel runs pluggable scanners against your own
infrastructure, normalises everything they find into a single `Finding` model, and produces
consolidated JSON and HTML security reports from one command.

> ⚠️ **Authorized use only.** Sentinel performs read-only inspection, but you must only run it
> against accounts, systems, and applications that you own or are explicitly authorized to audit.

---

## Why Sentinel

Most security tooling is either a single-purpose script or a heavyweight platform. Sentinel sits
in between: one clean, well-tested codebase where each security domain is an independent module
that shares common plumbing — a unified data model, report generation, and CLI. Adding a new
scanner is just adding a `BaseScanner` subclass; the CLI discovers it automatically.

## Features

- **Unified `Finding` model** — every scanner, whatever it inspects, emits the same structured
  finding (id, severity, description, **remediation**, evidence, resource).
- **Pluggable modules** — scanners auto-register via a registry; the CLI needs no changes to pick
  up a new one (open/closed principle).
- **Consolidated reports** — one run produces both machine-readable JSON and a styled HTML report,
  grouped by severity with a summary header.
- **Tested end-to-end** — every module is covered by `pytest`; AWS is mocked with `moto`, so tests
  never touch a real account.

### Available modules

| Module | Domain | Checks |
|--------|--------|--------|
| `cloudscan` | AWS misconfiguration | Public S3 buckets · Security groups open to `0.0.0.0/0` on SSH/RDP · IAM users without MFA |
| `logwatch` | Log analysis (SIEM-lite) | SSH brute-force detection · direct privileged (root/admin) logins |
| `webscan` | Web application | Missing HTTP security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options) |
| `netmon` | Network traffic | Port-scan detection · host-sweep detection (from a flow log) |

Plus a **Next.js + Tailwind dashboard** (`dashboard/`) that visualises any `report.json`.

## Architecture

```
sentinel/
├─ core/            # shared kernel
│   ├─ finding.py   # Finding model + Severity enum
│   ├─ scanner.py   # BaseScanner ABC + auto-registration registry
│   ├─ config.py    # YAML config loader
│   └─ report.py    # JSON + HTML report generation
├─ modules/         # each is a BaseScanner subclass (checks/ = one function per rule)
│   ├─ cloudscan/   # AWS misconfiguration scanner
│   ├─ logwatch/    # auth-log analysis
│   ├─ webscan/     # HTTP security headers
│   └─ netmon/      # network flow analysis
├─ templates/       # HTML report template
└─ cli.py           # Typer CLI: list-scanners, scan <name>, scan-all

dashboard/          # Next.js + Tailwind UI that renders a report.json
```

Data flow:

```
scanner.run() ─▶ list[Finding] ─▶ aggregate ─▶ report.json + report.html
```

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/citizen204/sentinel-toolkit.git
cd sentinel-toolkit
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Usage

```bash
# List the scanners available in this build
sentinel list-scanners

# Run a single scanner (uses your default AWS credentials/profile)
sentinel scan cloudscan

# Run every registered scanner into one consolidated report
sentinel scan-all

# Choose output format and directory
sentinel scan cloudscan --format html --output-dir reports
```

Reports are written to `reports/report-<timestamp>.{json,html}`.

### Configuration

Pass a YAML config with `--config`:

```yaml
# sentinel.yaml
aws_profile: my-audit-profile          # cloudscan
target_url: https://app.example.com    # webscan
log_paths:                             # logwatch
  - /var/log/auth.log
capture_file: flows.txt                # netmon (src_ip dst_ip dst_port per line)
output_dir: reports
```

```bash
sentinel scan cloudscan --config sentinel.yaml
sentinel scan-all --config sentinel.yaml
```

### Dashboard

```bash
cd dashboard
npm install
npm run dev            # http://localhost:3000
```

The dashboard reads `dashboard/public/report.json`; drop a real report there to view your own
findings. See [dashboard/README.md](dashboard/README.md).

## What `cloudscan` checks

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `CLOUD-S3-PUBLIC` | High | S3 bucket ACL grants access to a public group (AllUsers/AuthenticatedUsers) |
| `CLOUD-SG-OPEN-INGRESS` | High | Security group allows `0.0.0.0/0` inbound on SSH (22) or RDP (3389) |
| `CLOUD-IAM-NO-MFA` | Medium | IAM user has no MFA device enabled |

Every finding includes a concrete **remediation** step — Sentinel tells you not just what is wrong
but how to fix it.

## Testing

```bash
pytest -q
```

All AWS interactions are mocked with `moto`; the test suite runs fully offline.

## Tech stack

**Toolkit:** Python 3.11 · Pydantic · Typer · Jinja2 · boto3 · requests · pytest · moto · responses
**Dashboard:** Next.js · React · Tailwind CSS · TypeScript

## License

Released under the MIT License — see [LICENSE](LICENSE).

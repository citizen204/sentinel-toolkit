# 🛡️ Sentinel

**A modular, defensive security toolkit — one command scans your infrastructure across four
domains and produces a single, actionable report.**

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)
![Type](https://img.shields.io/badge/security-defensive-informational.svg)

Sentinel runs pluggable scanners — cloud, logs, web, and network — normalises everything they
find into one `Finding` model, and generates consolidated **JSON + HTML reports** plus a
**Next.js dashboard**. Adding a new scanner is just adding a subclass; the CLI discovers it
automatically.

> ⚠️ **Authorized use only.** Sentinel performs read-only inspection. Run it only against
> accounts, systems, and applications you own or are explicitly authorized to audit.

---

## 🚀 Quick start

```bash
git clone https://github.com/citizen204/sentinel-toolkit.git
cd sentinel-toolkit
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"

sentinel list-scanners      # see what's available
sentinel scan-all           # run everything, write reports/
```

Reports land in `reports/report-<timestamp>.{json,html}`.

## 👀 Example

```console
$ sentinel scan cloudscan --format both
JSON report: reports/report-20260628T120000.json
HTML report: reports/report-20260628T120000.html
Scan complete: 3 finding(s).
```

Each finding is structured and, crucially, tells you **how to fix it**:

```json
{
  "id": "CLOUD-S3-PUBLIC",
  "module": "cloudscan",
  "severity": "High",
  "title": "Publicly accessible S3 bucket",
  "description": "S3 bucket 'prod-backups' grants access to a public group (AllUsers).",
  "remediation": "Remove public ACL grants and enable S3 Block Public Access.",
  "resource": "prod-backups"
}
```

## 🧩 Modules

| Module | Domain | What it catches |
|--------|--------|-----------------|
| **`cloudscan`** | AWS misconfiguration | Public S3 buckets · security groups open to `0.0.0.0/0` on SSH/RDP · IAM users without MFA |
| **`logwatch`** | Log analysis (SIEM-lite) | SSH brute-force attempts · direct `root`/`admin` logins |
| **`webscan`** | Web application | Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options) |
| **`netmon`** | Network traffic | Port scans · host sweeps (from a flow log) |

<details>
<summary><b>Full rule reference</b></summary>

| Rule ID | Module | Severity |
|---------|--------|----------|
| `CLOUD-S3-PUBLIC` | cloudscan | High |
| `CLOUD-SG-OPEN-INGRESS` | cloudscan | High |
| `CLOUD-IAM-NO-MFA` | cloudscan | Medium |
| `LOG-BRUTEFORCE` | logwatch | High |
| `LOG-ROOT-LOGIN` | logwatch | Medium |
| `WEB-MISSING-HEADER` | webscan | Low–Medium |
| `NET-PORT-SCAN` | netmon | High |
| `NET-HOST-SWEEP` | netmon | Medium |

</details>

## 🏗️ How it works

Everything hangs off one idea: **every scanner emits the same `Finding`**, so reports and the
dashboard never care which module produced what.

```
scanner.run(config) ──▶ list[Finding] ──▶ aggregate ──▶ report.json + report.html ──▶ dashboard
```

```
sentinel/
├─ core/            # the shared kernel
│   ├─ finding.py   #   Finding model + Severity enum
│   ├─ scanner.py   #   BaseScanner ABC + auto-registration registry
│   ├─ config.py    #   YAML config loader
│   └─ report.py    #   JSON + HTML report generation
├─ modules/         # each module = a BaseScanner subclass (checks/ = one function per rule)
│   ├─ cloudscan/  logwatch/  webscan/  netmon/
├─ templates/       # HTML report template
└─ cli.py           # Typer CLI: list-scanners · scan <name> · scan-all

dashboard/          # Next.js + Tailwind UI that renders any report.json
```

**Design highlights**

- **Open/closed** — new modules register themselves via `__init_subclass__`; the CLI needs zero
  changes to pick them up.
- **Isolated failures** — one broken scanner never crashes `scan-all`; the error is reported as a
  finding and the rest keep running.
- **Remediation-first** — a finding that says what's wrong but not how to fix it is only half done.
- **Tested end-to-end** — AWS is mocked with `moto`, HTTP with `responses`; the suite runs fully
  offline.

## 📊 Dashboard

A Next.js + Tailwind UI: severity summary, per-severity filtering, and a card per finding.

![Sentinel dashboard](docs/assets/dashboard.png)

```bash
cd dashboard
npm install
npm run dev            # http://localhost:3000
```

It reads `dashboard/public/report.json` (a sample ships with the repo). To view your own data:

```bash
sentinel scan-all --format json --output-dir reports
cp reports/report-*.json dashboard/public/report.json
```

## ⚙️ Configuration

Point scanners at real targets with a YAML file:

```yaml
# sentinel.yaml
aws_profile: my-audit-profile          # cloudscan
target_url: https://app.example.com    # webscan
log_paths:                             # logwatch
  - /var/log/auth.log
capture_file: flows.txt                # netmon — "src_ip dst_ip dst_port" per line
output_dir: reports
```

```bash
sentinel scan-all --config sentinel.yaml
```

## ✅ Testing

```bash
pytest -q
```

Every module is covered; no test touches a real cloud account, host, or network.

## 🗺️ Roadmap

- `cloudscan`: unencrypted EBS/RDS, root access keys, password policy
- `netmon`: optional live capture via scapy (feeds the same flow analysis)
- Dashboard: upload/drag-and-drop a report, trend view across scans
- `Config.ignore_ids` to suppress accepted-risk findings

## 🛠️ Tech stack

**Toolkit** — Python 3.11 · Pydantic · Typer · Jinja2 · boto3 · requests · pytest · moto · responses
**Dashboard** — Next.js · React · Tailwind CSS · TypeScript

## 📄 License

MIT — see [LICENSE](LICENSE).

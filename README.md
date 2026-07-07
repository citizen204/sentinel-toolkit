<div align="center">

# 🛡️ Sentinel

### One command. Four attack surfaces. One actionable report.

**Sentinel is a modular, defensive security toolkit.** It scans your cloud, logs, web apps, and
network with pluggable scanners, normalises everything into one finding model, and produces a
single prioritised report — with a concrete fix for every issue.

[![CI](https://github.com/citizen204/sentinel-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/citizen204/sentinel-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-defensive-informational.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

[Quick start](#-quick-start) · [Modules](#-modules) · [Dashboard](#-dashboard) · [How it works](#%EF%B8%8F-how-it-works) · [Roadmap](#%EF%B8%8F-roadmap)

<img src="docs/assets/dashboard.png" alt="Sentinel dashboard" width="820">

</div>

> ⚠️ **Authorized use only.** Sentinel performs read-only inspection. Run it only against
> accounts, systems, and applications you own or are explicitly authorized to audit.

---

## ✨ Why Sentinel

Security tooling is usually either a throwaway script or a heavyweight platform. Sentinel is the
middle ground — **one clean, tested codebase where each security domain is an independent module**
sharing common plumbing:

- 🧩 **Pluggable by design** — every scanner is a `BaseScanner` subclass that self-registers. Add a
  module, and the CLI picks it up with zero wiring changes.
- 🎯 **Remediation-first** — a finding that says *what's* wrong but not *how* to fix it is only half
  done. Every finding carries a concrete remediation step.
- 🧱 **One model to rule them all** — cloud, log, web, and network results all become the same
  `Finding`, so reports and the dashboard never care which scanner produced what.
- 🛟 **Resilient** — one broken scanner never crashes the run; its failure is reported as a finding
  and the rest keep going.
- 📤 **SARIF-native** — export to SARIF 2.1.0 and pipe findings straight into **GitHub code
  scanning**; every rule is tagged with a category and MITRE/OWASP/AWS reference.
- ✅ **Genuinely tested** — 70+ tests, CI on every push. AWS is mocked with `moto`, HTTP with
  `responses`, packets with `scapy` — the suite runs fully offline.

## 🧩 Modules

| Module | Domain | What it catches |
|:------:|--------|-----------------|
| ☁️ **`cloudscan`** | AWS misconfiguration | Public S3 buckets · security groups open to `0.0.0.0/0` on SSH/RDP · IAM users without MFA |
| 📜 **`logwatch`** | Log analysis (SIEM-lite) | SSH brute-force attempts · direct `root`/`admin` logins |
| 🌐 **`webscan`** | Web application | Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options) |
| 📡 **`netmon`** | Network traffic | Port scans · host sweeps — from a flow log **or a live/pcap capture via scapy** |

<details>
<summary><b>Full rule reference</b></summary>

| Rule ID | Module | Severity |
|---------|--------|:--------:|
| `CLOUD-S3-PUBLIC` | cloudscan | High |
| `CLOUD-SG-OPEN-INGRESS` | cloudscan | High |
| `CLOUD-IAM-NO-MFA` | cloudscan | Medium |
| `LOG-BRUTEFORCE` | logwatch | High |
| `LOG-ROOT-LOGIN` | logwatch | Medium |
| `WEB-MISSING-HEADER` | webscan | Low–Medium |
| `NET-PORT-SCAN` | netmon | High |
| `NET-HOST-SWEEP` | netmon | Medium |

</details>

## 🚀 Quick start

```bash
git clone https://github.com/citizen204/sentinel-toolkit.git
cd sentinel-toolkit
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"

sentinel list-scanners      # what's available
sentinel scan-all           # run everything → reports/
```

## 🎯 Usage

```console
$ sentinel scan cloudscan --format both
JSON report: reports/report-20260628T120000.json
HTML report: reports/report-20260628T120000.html
Scan complete: 3 finding(s).
```

Every finding is structured and tells you **how to fix it**:

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

```bash
sentinel init-config                       # scaffold a sentinel.yaml to edit
sentinel scan <module>                     # run one scanner
sentinel scan-all                          # run every registered scanner
sentinel scan-all --exclude cloudscan      # skip a scanner (or --include webscan,logwatch)
sentinel scan-all --format sarif           # SARIF 2.1.0 → GitHub code scanning
sentinel scan-all --format all             # json + html + sarif at once
```

**Output formats:** `json` · `html` · `both` (default) · `sarif` · `all`. Invalid values are
rejected instead of silently producing nothing.

## 📊 Dashboard

A Next.js + Tailwind UI: severity summary, per-severity filtering, a card per finding, and
**drag-and-drop** to load any `report.json`.

```bash
cd dashboard
npm install
npm run dev            # http://localhost:3000
```

<div align="center"><img src="docs/assets/dashboard.png" alt="dashboard" width="720"></div>

## 🏗️ How it works

Everything hangs off one idea: **every scanner emits the same `Finding`.**

```
scanner.run(config) ──▶ list[Finding] ──▶ aggregate + filter ──▶ report.json + report.html ──▶ dashboard
```

```
sentinel/
├─ core/            # shared kernel: Finding · BaseScanner registry · config · report
├─ modules/         # cloudscan · logwatch · webscan · netmon (checks/ = one function per rule)
├─ templates/       # HTML report template
└─ cli.py           # Typer CLI: list-scanners · scan <name> · scan-all
dashboard/          # Next.js + Tailwind UI for any report.json
```

Adding a scanner is a subclass — no core changes:

```python
from sentinel.core.scanner import BaseScanner
from sentinel.core.finding import Finding, Severity

class MyScanner(BaseScanner):
    name = "myscanner"
    def run(self, config) -> list[Finding]:
        return [Finding(id="MY-001", module="myscanner", severity=Severity.LOW,
                        title="...", description="...", remediation="...")]
```

## ⚙️ Configuration

Generate a starter file with `sentinel init-config`, then edit:

```yaml
# sentinel.yaml
aws_profile: my-audit-profile          # cloudscan
aws_regions:                           # cloudscan — scan security groups per region
  - us-east-1
  - ap-southeast-2
target_url: https://app.example.com    # webscan
log_paths:                             # logwatch
  - /var/log/auth.log
capture_file: capture.pcap             # netmon — a flow log OR a .pcap/.pcapng
ignore_ids:                            # suppress accepted-risk findings by rule id
  - CLOUD-IAM-NO-MFA
output_dir: reports
```

## ✅ Testing & CI

```bash
pytest -q          # 70+ tests, fully offline
```

Every push and pull request runs the suite on GitHub Actions (see the CI badge above). No test
touches a real cloud account, host, or network.

## 🗺️ Roadmap

- [x] Four scanner modules + unified reporting + dashboard
- [x] Failure isolation, pagination, ignore-list, scapy capture
- [x] SARIF output, multi-region AWS scanning, `init-config`, `--include/--exclude`
- [ ] More cloud checks (unencrypted EBS/RDS, root access keys, password policy)
- [ ] Trend view across scans in the dashboard
- [ ] Markdown output format

## 🤝 Contributing

Issues and PRs are welcome. Each module is self-contained: add a `BaseScanner` subclass under
`sentinel/modules/`, register it, and ship it with tests. Run `pytest -q` before opening a PR.

## 👤 About

Built by **Xi (Chilton) Chen**, a cybersecurity undergraduate at the University of Adelaide, as a
hands-on portfolio project — a place to turn security concepts (access control, SIEM, web hardening,
network recon) into real, tested code. Feedback is genuinely welcome.

## 📄 License

[MIT](LICENSE) © Xi (Chilton) Chen

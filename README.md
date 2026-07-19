<div align="center">

# 🛡️ Sentinel

### One command. Four attack surfaces. One actionable report.

**Sentinel is a modular, defensive security toolkit.** It scans your cloud, logs, web apps, and
network with pluggable scanners, normalises everything into one finding model, and produces a
single prioritised report — with a concrete fix for every issue.

[![CI](https://github.com/citizen204/sentinel-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/citizen204/sentinel-toolkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/citizen204/sentinel-toolkit/actions/workflows/codeql.yml/badge.svg)](https://github.com/citizen204/sentinel-toolkit/actions/workflows/codeql.yml)
[![Supply chain](https://github.com/citizen204/sentinel-toolkit/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/citizen204/sentinel-toolkit/actions/workflows/supply-chain.yml)
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
- 🔍 **Audit-grade evidence** — every finding answers *which API* produced it, *what was observed*,
  *why that is a failure*, and *how to verify the fix* — with the account and region attached.
  A failed check is reported as unassessed, never as a pass.
- 🧱 **One model to rule them all** — cloud, log, web, and network results all become the same
  `Finding`, bound to a structured **`Asset`** (provider/account/region/type/id) instead of a bare
  string — the difference between a flat report and a real security tool.
- 📚 **Rule catalog** — rule metadata (severity, category, MITRE/OWASP refs, confidence) lives in a
  central `Rule` registry, not scattered across check code. Browse it with `sentinel rules`.
- 🔕 **Grown-up noise control** — accept risks with expiring, reasoned **suppressions** (kept and
  counted in the report, not silently dropped), and **diff scans** for new/resolved/persisting
  findings via stable fingerprints.
- 🛟 **Resilient** — one broken scanner never crashes the run; its failure is reported as a finding
  and the rest keep going.
- 📤 **SARIF-native** — export to SARIF 2.1.0 and pipe findings straight into **GitHub code
  scanning**; every rule is tagged with a category and MITRE/OWASP/AWS reference.
- ✅ **Genuinely tested** — 70+ tests, CI on every push. AWS is mocked with `moto`, HTTP with
  `responses`, packets with `scapy` — the suite runs fully offline.

## 🧩 Modules

| Module | Domain | What it catches |
|:------:|--------|-----------------|
| ☁️ **`cloudscan`** | AWS misconfiguration | S3 (public ACL, no encryption/versioning/Block-Public-Access) · security groups open to `0.0.0.0/0` / `::/0` on SSH/RDP (all regions) · IAM (no MFA, no password policy, **admin-equivalent privileges via user/group/inline/wildcard policies**) · EBS/RDS unencrypted |
| 📜 **`logwatch`** | Log analysis (SIEM-lite) | SSH brute-force attempts · direct `root`/`admin` logins |
| 🌐 **`webscan`** | Web application | Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options) |
| 📡 **`netmon`** | Network traffic | Port scans · host sweeps — from a flow log **or a live/pcap capture via scapy** |

<details>
<summary><b>Full rule reference</b></summary>

| Rule ID | Module | Severity |
|---------|--------|:--------:|
| `CLOUD-S3-PUBLIC` | cloudscan | High |
| `CLOUD-S3-NO-ENCRYPTION` | cloudscan | Medium |
| `CLOUD-S3-NO-VERSIONING` | cloudscan | Low |
| `CLOUD-S3-NO-BPA` | cloudscan | Medium |
| `CLOUD-SG-OPEN-INGRESS` | cloudscan | High |
| `CLOUD-IAM-NO-MFA` | cloudscan | Medium |
| `CLOUD-IAM-NO-PASSWORD-POLICY` | cloudscan | Medium |
| `CLOUD-IAM-EFFECTIVE-ADMIN` | cloudscan | High |
| `CLOUD-EBS-UNENCRYPTED` | cloudscan | Medium |
| `CLOUD-RDS-UNENCRYPTED` | cloudscan | High |
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

Or with Docker:

```bash
docker build -t sentinel .
docker run --rm -v "$PWD/reports:/work/reports" sentinel scan-all
```

The image runs as a non-root user and pins its base image by digest; every push builds it,
generates a CycloneDX SBOM, and scans it with Trivy (results go to the Security tab).

`cloudscan` needs only read-only AWS permissions — a least-privilege policy is in
[docs/aws-iam-policy.json](docs/aws-iam-policy.json).

**Auditing a whole organisation:** create that read-only role in each account (trusting your
audit principal), list the roles under `aws_accounts`, and give your principal `sts:AssumeRole`
on them. Sentinel assumes each role in turn, attributes every finding to its account, and keeps
scanning the remaining accounts if one is unreachable.

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
  "api": "s3:GetBucketAcl",
  "rationale": "The bucket ACL grants to AllUsers; that group resolves to anyone on the internet.",
  "evidence": { "bucket": "prod-backups", "public_grantees": ["...AllUsers"] },
  "remediation": "Remove public ACL grants and enable S3 Block Public Access.",
  "verify": "aws s3api get-bucket-acl --bucket prod-backups",
  "asset": { "provider": "aws", "type": "s3_bucket", "id": "prod-backups", "account_id": "123456789012" }
}
```

```bash
sentinel rules                             # browse the rule catalog
sentinel init-config                       # scaffold a sentinel.yaml to edit
sentinel scan <module>                     # run one scanner
sentinel scan-all                          # run every registered scanner
sentinel scan-all --exclude cloudscan      # skip a scanner (or --include webscan,logwatch)
sentinel scan-all --format sarif           # SARIF 2.1.0 → GitHub code scanning
sentinel scan-all --format all             # json + html + sarif at once
```

**Output formats:** `json` · `html` · `both` (default) · `sarif` · `all`. Invalid values are
rejected instead of silently producing nothing.

Track posture over time by diffing two JSON reports:

```bash
sentinel diff reports/last-week.json reports/today.json
```

```console
New:        1
Resolved:   2
Persisting: 7
Unassessed: 3

  ? [High] CLOUD-RDS-UNENCRYPTED  legacy-db

'?' findings were present before and were not covered by the newer run.
They are not resolved - their status is unknown.

Warning: The newer run did not fully cover: cloudscan.
```

## 🧾 "Resolved" has to be earned

A finding that disappears between two scans has two possible explanations: someone fixed it, or
nobody looked. A scanner that can't tell the difference will eventually report an unscanned
region as remediated — and talk an operator out of a real exposure.

So every report carries what the run actually **covered**, not just what it found:

```json
{
  "schema_version": "2.0",
  "run_id": "b6f1…", "tool_version": "0.2.0", "build_commit": "a2256698…",
  "ruleset_digest": "4f53cda18c2baa0c", "config_digest": "9c1185a5c5e9fc54",
  "coverage": {
    "units": [
      { "scanner": "cloudscan", "account_id": "123456789012",
        "region": "ap-southeast-2", "check": "rds_encryption", "status": "ok" },
      { "scanner": "netmon", "status": "skipped" }
    ],
    "rules": ["CLOUD-SG-OPEN-INGRESS", "..."]
  }
}
```

Coverage is a list of **concrete scopes that were actually attempted**, not a set of flat
lists. Two accounts scanned in one region each is two units — not the four that
`accounts × regions` would imply. And it is recorded during execution, never inferred from
the findings: derive it from findings and a clean account produces an empty scope, which
would make the cleanest scan the one making the widest claim.

`sentinel diff` calls a finding **resolved** only when the newer run has a matching unit
that ran to completion. Everything else is **unassessed**. Which means:

- a role that lost `rds:DescribeDBInstances` → `unassessed`, not resolved
- a region dropped from `aws_regions` → `unassessed`, not resolved
- a rule switched off, or a profile change → `unassessed`, not resolved
- a scanner with no input configured → reported as `SCANNER-SKIPPED`, never as a clean pass
- one account that failed to assume → only *that* account is unassessed; the rest still resolve

The two digests catch the subtler case: if the rule catalog or the config changed between runs,
the diff says so, because a renamed or re-rated rule changes finding identity and can mimic a
fix. `ruleset_digest` covers each rule's `revision` as well as its metadata, so changing what a
check *does* is visible even when its title and severity stay the same. The dashboard computes
all of this from the same fields, so the UI and the CLI can't disagree.

Gate CI on it:

```bash
sentinel scan-all --fail-on High           # exit 2 if anything High or worse is open
sentinel scan-all --fail-on-incomplete     # exit 3 if any scanner did not complete
```

Both are opt-in — the default exit code stays 0 — and they are separate codes because
"we found problems" and "we could not look" need different responses.

## 📋 Compliance mapping

Rules that correspond to a **CIS AWS Foundations Benchmark** control carry the control id, and
`profile: cis` runs only those:

```console
$ sentinel rules
CLOUD-IAM-EFFECTIVE-ADMIN  [High/Access Control]    ...  (CIS-AWS-1.4.0:1.16)
CLOUD-RDS-UNENCRYPTED      [High/Data Protection]   ...  (CIS-AWS-3.0.0:2.3.1)
CLOUD-S3-NO-BPA            [Medium/Data Exposure]   ...  (CIS-AWS-3.0.0:2.1.4)
CLOUD-SG-OPEN-INGRESS      [High/Network Exposure]  ...  (CIS-AWS-3.0.0:5.2, CIS-AWS-3.0.0:5.3)
```

Only **4 of 16** cloud rules are mapped, and that number is deliberate. Every id is traced to
AWS Security Hub's published CIS control table — none are recalled from memory, because a
plausible-looking wrong control id is worse than no mapping at all. The rules that *look* like
they should map but don't, and the benchmark controls Sentinel doesn't yet cover, are both
listed in **[docs/compliance.md](docs/compliance.md)**. Sentinel is not a certified CIS
assessment tool.

## 📊 Dashboard

A Next.js + Tailwind UI: severity summary, per-severity filtering, a card per finding, and
**drag-and-drop** to load any `report.json`.

Drop in **several runs at once** and it becomes a posture tracker:

- **Since the previous run** — new / resolved / persisting / **unassessed**, matched on the same
  `dedupe_key` the CLI's `sentinel diff` uses and gated by the same coverage rules, so the UI and
  the CLI can't disagree.
- **Open findings over time** — a severity-stacked bar per run (suppressed findings excluded,
  since an accepted risk isn't open).
- **By module / account / region** — where the risk actually concentrates.

Runs are ordered by `generated_at`, so it doesn't matter what order you drop them in.

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
├─ core/            # shared kernel: Finding · Asset · Rule catalog · scanner registry · report
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
aws_regions:                           # cloudscan — omit/leave empty to scan every
  - us-east-1                          #   region enabled for the account (discovered
  - ap-southeast-2                     #   via ec2:DescribeRegions)
aws_accounts:                          # optional: audit many accounts via AssumeRole
  - role_arn: arn:aws:iam::111111111111:role/SentinelAudit
    regions: [us-east-1, ap-southeast-2]
  - role_arn: arn:aws:iam::222222222222:role/SentinelAudit
target_url: https://app.example.com    # webscan
log_paths:                             # logwatch
  - /var/log/auth.log
capture_file: capture.pcap             # netmon — a flow log OR a .pcap/.pcapng
ignore_ids:                            # DEPRECATED — prefer suppressions (audit trail).
  - CLOUD-IAM-NO-MFA                   #   Error findings can never be ignored.
suppressions:                          # accepted risks: kept in the report, marked suppressed
  - rule: CLOUD-IAM-NO-MFA             # narrow by dedupe_key / rule / resource /
    resource: deploy-bot               #   account_id / region / asset_type / provider
    account_id: "123456789012"         # pin to one account so it can't match elsewhere
    reason: service account, MFA not applicable
    created_by: chilton                # audit trail
    ticket: SEC-123
    expires: 2027-01-01                # optional; suppression lapses after this date
profile: baseline                      # baseline = high-confidence, high-risk rules only
                                       # strict  = also the noisier / compliance-oriented
                                       #           ones (e.g. S3 versioning)
                                       # cis     = only rules mapped to a CIS AWS control
                                       #           (see docs/compliance.md)
rules:                                 # per-rule overrides
  LOG-BRUTEFORCE:
    threshold: 10                      # tune threshold-based rules
  CLOUD-S3-NO-VERSIONING:
    enabled: false                     # turn a rule off
  CLOUD-IAM-NO-MFA:
    severity: High                     # re-rate for your risk model
output_dir: reports
```

Scanner and check failures are never hidden by profiles or rule config — only real
findings can be tuned away.

## ✅ Testing & CI

```bash
pytest -q          # 200+ tests, fully offline
```

Every push and pull request runs on GitHub Actions (see the badges above): **pytest + `ruff`
lint** for the toolkit, a **dashboard eslint + build** job, and **CodeQL** static analysis for
Python and TypeScript.

The **supply-chain** job builds the container, asserts it doesn't run as root, checks the image
against `requirements.lock`, emits a **CycloneDX SBOM**, and runs **Trivy** twice on purpose:

- **fixable CRITICAL/HIGH in our own dependencies → the build fails.** These are actionable here.
- **everything else, including unfixable base-image CVEs → reported to the Security tab.**
  Failing on those would mean a red build nobody can turn green, which just teaches people to
  ignore it.

Every action is pinned to a full commit SHA and every tool image to a digest — a tag can be
repointed by whoever owns it, a digest can't. **Dependabot** keeps pip, npm, Actions, and the
base image current. No test touches a real cloud account, host, or network.

## 🗺️ Roadmap

- [x] Four scanner modules + unified reporting + dashboard
- [x] Failure isolation, pagination, ignore-list, scapy capture
- [x] SARIF output, multi-region AWS scanning, `init-config`, `--include/--exclude`
- [x] Deeper cloud checks (S3 encryption/versioning/BPA, IAM password policy + admin, EBS/RDS encryption)
- [x] Production hygiene: CodeQL, Dependabot, Docker, SECURITY/CONTRIBUTING/CHANGELOG
- [x] Suppressions (rule/resource/expiry/reason) and `sentinel diff` (new/resolved/persisting)
- [x] CIS AWS Benchmark mapping (`profile: cis`) with the gaps written down, not papered over
- [x] Posture tracker in the dashboard: run history, diff, trend, and account/region rollups
- [x] Provable scan coverage: recorded coverage units, `unassessed` bucket, no silently-empty scans
- [x] Supply-chain gating: SHA-pinned actions, digest-pinned tools, dependency lock, blocking scan
- [x] `--fail-on` / `--fail-on-incomplete` exit codes, scan health in HTML and SARIF
- [ ] Published JSON Schema for the report format
- [ ] Resource-level error isolation, retry/backoff, cross-account concurrency
- [ ] IAM privilege-escalation chains and SCPs
- [ ] Signed OCI/PyPI releases with SLSA provenance
- [ ] Markdown output format

## 🤝 Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the checks to run,
and how to add a scanner or rule. Security reports: see [SECURITY.md](SECURITY.md). Release notes
live in [CHANGELOG.md](CHANGELOG.md).

## 👤 About

Built by **Xi (Chilton) Chen**, a cybersecurity undergraduate at the University of Adelaide, as a
hands-on portfolio project — a place to turn security concepts (access control, SIEM, web hardening,
network recon) into real, tested code. Feedback is genuinely welcome.

## 📄 License

[MIT](LICENSE) © Xi (Chilton) Chen

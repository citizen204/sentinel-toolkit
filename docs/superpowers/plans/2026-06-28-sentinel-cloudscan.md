# Sentinel cloudscan Module Implementation Plan (Phase 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. NOTE: if the account spend limit blocks subagents, execute inline in the main session instead — the TDD discipline is identical.

**Goal:** Build `cloudscan`, the first real Sentinel scanner module: a `BaseScanner` subclass that inspects an AWS account (via boto3) for three classic misconfigurations and emits `Finding` objects that flow through the existing report/CLI pipeline.

**Architecture:** Each check is a pure function `(boto3.Session) -> list[Finding]`, unit-tested in isolation with `moto` (mocked AWS — never touches a real account). `CloudScanner.run()` builds a session from `Config.aws_profile`, runs every check, and aggregates findings. The module auto-registers via `sentinel/modules/__init__.py`, so `sentinel scan-all` and a new `sentinel scan cloudscan` command pick it up with no core changes.

**Tech Stack:** Python 3.11+, boto3, moto (test-only), pytest. Builds on the Phase 1 core (`Finding`, `Severity`, `BaseScanner`, `Config`, report, CLI).

---

## Defensive / authorized-use note

`cloudscan` reads AWS configuration state (list/describe/get calls only — no mutations). It must only be run against an account you own or are explicitly authorized to audit. This is stated in the module docstring and (later) the README.

## File Structure

```
sentinel/modules/
├─ __init__.py                    # MODIFY: import cloudscan to register it
└─ cloudscan/
    ├─ __init__.py                # exports CloudScanner
    ├─ scanner.py                 # CloudScanner(BaseScanner) — wires checks
    └─ checks/
        ├─ __init__.py
        ├─ s3.py                  # check_public_buckets(session)
        ├─ security_groups.py     # check_open_security_groups(session)
        └─ iam.py                 # check_users_without_mfa(session)

sentinel/cli.py                   # MODIFY: add `scan <name>` cmd + DRY report helper

tests/
├─ conftest.py                    # MODIFY: add aws_credentials fixture
├─ test_cloudscan_s3.py
├─ test_cloudscan_sg.py
├─ test_cloudscan_iam.py
├─ test_cloudscan_scanner.py      # registration + integration (all checks)
└─ test_cli_scan.py               # `sentinel scan cloudscan` end-to-end
```

**Finding rule IDs (stable, one per rule; `resource` identifies the specific AWS resource):**
- `CLOUD-S3-PUBLIC` — public S3 bucket (severity High)
- `CLOUD-SG-OPEN-INGRESS` — security group open to 0.0.0.0/0 on a risky port (High)
- `CLOUD-IAM-NO-MFA` — IAM user without MFA (Medium)

All commands assume working directory `C:\Users\71513\Desktop\Sentinel`, branch `feat/cloudscan` (create it first), venv at `.venv`. Run tests via `.venv\Scripts\python.exe -m pytest`. Do not sign commits; if signing errors use `git -c commit.gpgsign=false commit ...`.

---

### Task 0: Branch + dependencies + package skeleton

**Files:**
- Create branch `feat/cloudscan`
- Modify: `pyproject.toml`
- Create: `sentinel/modules/cloudscan/__init__.py`, `sentinel/modules/cloudscan/scanner.py` (stub), `sentinel/modules/cloudscan/checks/__init__.py`

- [ ] **Step 1: Create the feature branch**

```bash
git checkout master
git checkout -b feat/cloudscan
```

- [ ] **Step 2: Add boto3 (runtime) and moto (dev) to `pyproject.toml`**

In `[project] dependencies`, add `"boto3>=1.34"` so the list becomes:
```toml
dependencies = [
    "pydantic>=2.6",
    "typer>=0.12",
    "jinja2>=3.1",
    "pyyaml>=6.0",
    "boto3>=1.34",
]
```
In `[project.optional-dependencies]`, extend dev:
```toml
[project.optional-dependencies]
dev = ["pytest>=8.0", "moto>=5.0"]
```

- [ ] **Step 3: Reinstall so new deps are present**

Run: `.venv\Scripts\python.exe -m pip install -e ".[dev]"`
Expected: installs boto3, botocore, moto (and their deps) without error.

- [ ] **Step 4: Create the package skeleton**

`sentinel/modules/cloudscan/checks/__init__.py`: empty file.

`sentinel/modules/cloudscan/scanner.py` (stub — real body in Task 4):
```python
from __future__ import annotations
```

`sentinel/modules/cloudscan/__init__.py` (leave the export commented until Task 4 defines the class):
```python
# CloudScanner is exported once implemented in scanner.py (Task 4).
```

- [ ] **Step 5: Verify the suite still passes (no behavior added yet)**

Run: `.venv\Scripts\python.exe -m pytest -q`
Expected: PASS (22 passed — unchanged from Phase 1).

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml sentinel/modules/cloudscan
git commit -m "chore(cloudscan): add boto3/moto deps and package skeleton"
```

---

### Task 1: S3 public-bucket check

**Files:**
- Create: `sentinel/modules/cloudscan/checks/s3.py`
- Modify: `tests/conftest.py` (add `aws_credentials` fixture)
- Test: `tests/test_cloudscan_s3.py`

- [ ] **Step 1: Add the `aws_credentials` fixture to `tests/conftest.py`**

Append to the existing `tests/conftest.py` (keep the existing `sample_findings` fixture):
```python
@pytest.fixture
def aws_credentials(monkeypatch):
    """Fake AWS creds so boto3 never reaches a real account under moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
```

- [ ] **Step 2: Write the failing test** — `tests/test_cloudscan_s3.py`:
```python
import boto3
from moto import mock_aws
from sentinel.modules.cloudscan.checks.s3 import check_public_buckets
from sentinel.core.finding import Severity


@mock_aws
def test_public_bucket_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="private-bucket")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    findings = check_public_buckets(session)

    flagged = {(f.id, f.resource) for f in findings}
    assert ("CLOUD-S3-PUBLIC", "public-bucket") in flagged
    assert all(f.resource != "private-bucket" for f in findings)
    public = next(f for f in findings if f.resource == "public-bucket")
    assert public.severity is Severity.HIGH
    assert public.module == "cloudscan"


@mock_aws
def test_no_buckets_yields_no_findings(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    assert check_public_buckets(session) == []
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_s3.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.modules.cloudscan.checks.s3'`

- [ ] **Step 4: Write minimal implementation** — `sentinel/modules/cloudscan/checks/s3.py`:
```python
from __future__ import annotations

from sentinel.core.finding import Finding, Severity

_PUBLIC_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _is_public(grants: list[dict]) -> bool:
    for grant in grants:
        uri = grant.get("Grantee", {}).get("URI", "")
        if uri in _PUBLIC_URIS:
            return True
    return False


def check_public_buckets(session) -> list[Finding]:
    """Flag S3 buckets whose ACL grants access to a public group."""
    s3 = session.client("s3")
    findings: list[Finding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        if _is_public(grants):
            findings.append(
                Finding(
                    id="CLOUD-S3-PUBLIC",
                    module="cloudscan",
                    severity=Severity.HIGH,
                    title="Publicly accessible S3 bucket",
                    description=(
                        f"S3 bucket '{name}' grants access to a public group "
                        f"(AllUsers/AuthenticatedUsers)."
                    ),
                    remediation=(
                        "Remove public ACL grants and enable S3 Block Public Access."
                    ),
                    evidence={"bucket": name, "grants": grants},
                    resource=name,
                )
            )
    return findings
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_s3.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add sentinel/modules/cloudscan/checks/s3.py tests/test_cloudscan_s3.py tests/conftest.py
git commit -m "feat(cloudscan): add public S3 bucket check"
```

---

### Task 2: Security-group open-ingress check

**Files:**
- Create: `sentinel/modules/cloudscan/checks/security_groups.py`
- Test: `tests/test_cloudscan_sg.py`

- [ ] **Step 1: Write the failing test** — `tests/test_cloudscan_sg.py`:
```python
import boto3
from moto import mock_aws
from sentinel.modules.cloudscan.checks.security_groups import (
    check_open_security_groups,
)


def _make_sg(ec2, from_port, to_port, cidr):
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(
        GroupName=f"sg-{from_port}", Description="test", VpcId=vpc
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": from_port, "ToPort": to_port,
            "IpRanges": [{"CidrIp": cidr}],
        }],
    )
    return sg


@mock_aws
def test_ssh_open_to_world_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    sg = _make_sg(ec2, 22, 22, "0.0.0.0/0")

    findings = check_open_security_groups(session)

    match = [f for f in findings if f.resource == sg]
    assert len(match) == 1
    assert match[0].id == "CLOUD-SG-OPEN-INGRESS"
    assert match[0].evidence["port"] == 22


@mock_aws
def test_restricted_cidr_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    sg = _make_sg(ec2, 22, 22, "203.0.113.0/24")

    findings = check_open_security_groups(session)

    assert all(f.resource != sg for f in findings)


@mock_aws
def test_open_but_non_risky_port_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    sg = _make_sg(ec2, 8080, 8080, "0.0.0.0/0")

    findings = check_open_security_groups(session)

    assert all(f.resource != sg for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_sg.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.modules.cloudscan.checks.security_groups'`

- [ ] **Step 3: Write minimal implementation** — `sentinel/modules/cloudscan/checks/security_groups.py`:
```python
from __future__ import annotations

from sentinel.core.finding import Finding, Severity

# Ports that are dangerous to expose to the whole internet.
RISKY_PORTS = {22: "SSH", 3389: "RDP"}


def _covers(perm: dict, port: int) -> bool:
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _open_to_world(perm: dict) -> bool:
    return any(rng.get("CidrIp") == "0.0.0.0/0" for rng in perm.get("IpRanges", []))


def check_open_security_groups(session) -> list[Finding]:
    """Flag security groups allowing 0.0.0.0/0 inbound on a risky port."""
    ec2 = session.client("ec2")
    findings: list[Finding] = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        group_id = sg["GroupId"]
        for perm in sg.get("IpPermissions", []):
            if not _open_to_world(perm):
                continue
            for port, label in RISKY_PORTS.items():
                if _covers(perm, port):
                    findings.append(
                        Finding(
                            id="CLOUD-SG-OPEN-INGRESS",
                            module="cloudscan",
                            severity=Severity.HIGH,
                            title=f"Security group open to the world on {label}",
                            description=(
                                f"Security group '{group_id}' allows 0.0.0.0/0 "
                                f"inbound on port {port} ({label})."
                            ),
                            remediation=(
                                f"Restrict inbound {label} (port {port}) to known "
                                f"IP ranges instead of 0.0.0.0/0."
                            ),
                            evidence={
                                "group_id": group_id, "port": port,
                                "cidr": "0.0.0.0/0",
                            },
                            resource=group_id,
                        )
                    )
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_sg.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add sentinel/modules/cloudscan/checks/security_groups.py tests/test_cloudscan_sg.py
git commit -m "feat(cloudscan): add open security group ingress check"
```

---

### Task 3: IAM users-without-MFA check

**Files:**
- Create: `sentinel/modules/cloudscan/checks/iam.py`
- Test: `tests/test_cloudscan_iam.py`

- [ ] **Step 1: Write the failing test** — `tests/test_cloudscan_iam.py`:
```python
import boto3
from moto import mock_aws
from sentinel.modules.cloudscan.checks.iam import check_users_without_mfa
from sentinel.core.finding import Severity


@mock_aws
def test_user_without_mfa_is_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="no-mfa-user")

    findings = check_users_without_mfa(session)

    assert len(findings) == 1
    assert findings[0].id == "CLOUD-IAM-NO-MFA"
    assert findings[0].resource == "no-mfa-user"
    assert findings[0].severity is Severity.MEDIUM


@mock_aws
def test_user_with_mfa_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="mfa-user")
    dev = iam.create_virtual_mfa_device(VirtualMFADeviceName="dev1")
    iam.enable_mfa_device(
        UserName="mfa-user",
        SerialNumber=dev["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="234567",
    )

    findings = check_users_without_mfa(session)

    assert all(f.resource != "mfa-user" for f in findings)


@mock_aws
def test_no_users_yields_no_findings(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    assert check_users_without_mfa(session) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_iam.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.modules.cloudscan.checks.iam'`

- [ ] **Step 3: Write minimal implementation** — `sentinel/modules/cloudscan/checks/iam.py`:
```python
from __future__ import annotations

from sentinel.core.finding import Finding, Severity


def check_users_without_mfa(session) -> list[Finding]:
    """Flag IAM users that have no MFA device enabled."""
    iam = session.client("iam")
    findings: list[Finding] = []
    for user in iam.list_users().get("Users", []):
        username = user["UserName"]
        devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not devices:
            findings.append(
                Finding(
                    id="CLOUD-IAM-NO-MFA",
                    module="cloudscan",
                    severity=Severity.MEDIUM,
                    title="IAM user without MFA",
                    description=f"IAM user '{username}' has no MFA device enabled.",
                    remediation="Enable an MFA device for this IAM user.",
                    evidence={"user": username},
                    resource=username,
                )
            )
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_iam.py -v`
Expected: PASS (3 passed). If `enable_mfa_device` raises under moto, keep the two robust tests (`test_user_without_mfa_is_flagged`, `test_no_users_yields_no_findings`) and report the moto limitation — do not weaken the check code.

- [ ] **Step 5: Commit**

```bash
git add sentinel/modules/cloudscan/checks/iam.py tests/test_cloudscan_iam.py
git commit -m "feat(cloudscan): add IAM users-without-MFA check"
```

---

### Task 4: CloudScanner class + registration

**Files:**
- Modify: `sentinel/modules/cloudscan/scanner.py`
- Modify: `sentinel/modules/cloudscan/__init__.py`
- Modify: `sentinel/modules/__init__.py`
- Test: `tests/test_cloudscan_scanner.py`

- [ ] **Step 1: Write the failing test** — `tests/test_cloudscan_scanner.py`:
```python
import boto3
from moto import mock_aws
from sentinel.core.scanner import all_scanners
from sentinel.core.config import Config


def test_cloudscan_is_registered():
    import sentinel.modules  # noqa: F401  triggers registration
    assert "cloudscan" in all_scanners()


@mock_aws
def test_run_aggregates_all_checks(aws_credentials):
    from sentinel.modules.cloudscan.scanner import CloudScanner

    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="s", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    iam = session.client("iam")
    iam.create_user(UserName="no-mfa-user")

    findings = CloudScanner().run(Config())

    ids = {f.id for f in findings}
    assert ids == {"CLOUD-S3-PUBLIC", "CLOUD-SG-OPEN-INGRESS", "CLOUD-IAM-NO-MFA"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_scanner.py -v`
Expected: FAIL — `cloudscan` not in registry / `ImportError: cannot import name 'CloudScanner'`

- [ ] **Step 3: Implement `CloudScanner`** — `sentinel/modules/cloudscan/scanner.py` (replace the stub):
```python
from __future__ import annotations

import boto3

from sentinel.core.finding import Finding
from sentinel.core.scanner import BaseScanner
from .checks.s3 import check_public_buckets
from .checks.security_groups import check_open_security_groups
from .checks.iam import check_users_without_mfa


class CloudScanner(BaseScanner):
    """Scans an AWS account for common misconfigurations (read-only)."""

    name = "cloudscan"

    def run(self, config) -> list[Finding]:
        if config.aws_profile:
            session = boto3.Session(profile_name=config.aws_profile)
        else:
            session = boto3.Session()
        findings: list[Finding] = []
        findings.extend(check_public_buckets(session))
        findings.extend(check_open_security_groups(session))
        findings.extend(check_users_without_mfa(session))
        return findings
```

- [ ] **Step 4: Export and register**

`sentinel/modules/cloudscan/__init__.py`:
```python
from .scanner import CloudScanner  # noqa: F401
```

`sentinel/modules/__init__.py` (was empty):
```python
from . import cloudscan  # noqa: F401  registers CloudScanner
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cloudscan_scanner.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add sentinel/modules/cloudscan/scanner.py sentinel/modules/cloudscan/__init__.py sentinel/modules/__init__.py tests/test_cloudscan_scanner.py
git commit -m "feat(cloudscan): add CloudScanner and auto-register module"
```

---

### Task 5: CLI `scan <name>` command

**Files:**
- Modify: `sentinel/cli.py`
- Test: `tests/test_cli_scan.py`

- [ ] **Step 1: Write the failing test** — `tests/test_cli_scan.py`:
```python
import json
from pathlib import Path
import boto3
from moto import mock_aws
from typer.testing import CliRunner
from sentinel.cli import app

runner = CliRunner()


def test_unknown_scanner_exits_nonzero():
    result = runner.invoke(app, ["scan", "does-not-exist"])
    assert result.exit_code == 1
    assert "Unknown scanner" in result.stdout


@mock_aws
def test_scan_cloudscan_writes_report(aws_credentials, tmp_path):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    result = runner.invoke(
        app,
        ["scan", "cloudscan", "--output-dir", str(tmp_path), "--format", "json"],
    )
    assert result.exit_code == 0, result.stdout
    json_files = list(Path(tmp_path).glob("report-*.json"))
    assert len(json_files) == 1
    payload = json.loads(json_files[0].read_text(encoding="utf-8"))
    ids = {f["id"] for f in payload["findings"]}
    assert "CLOUD-S3-PUBLIC" in ids
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cli_scan.py -v`
Expected: FAIL — Typer reports no command named `scan` (nonzero exit, "No such command").

- [ ] **Step 3: Refactor report-writing into a helper and add the `scan` command** — edit `sentinel/cli.py`.

Add this private helper above the commands (after the `app = typer.Typer(...)` block):
```python
def _emit_reports(findings, output_dir: str, fmt: str) -> None:
    if fmt in ("json", "both"):
        typer.echo(f"JSON report: {report_mod.write_json(findings, output_dir)}")
    if fmt in ("html", "both"):
        typer.echo(f"HTML report: {report_mod.write_html(findings, output_dir)}")
    typer.echo(f"Scan complete: {len(findings)} finding(s).")
```

Replace the body of the existing `scan_all` command's reporting section so it uses the helper. The full updated `scan_all` becomes:
```python
@app.command("scan-all")
def scan_all(
    config: str = typer.Option(None, "--config", help="Path to YAML config file."),
    fmt: str = typer.Option("both", "--format", help="json | html | both"),
    output_dir: str = typer.Option("reports", "--output-dir", help="Report output dir."),
) -> None:
    """Run every registered scanner and write a consolidated report."""
    cfg = load_config(config)
    findings = []
    for scanner_cls in all_scanners().values():
        findings.extend(scanner_cls().run(cfg))
    _emit_reports(findings, output_dir, fmt)
```

Add the new `scan` command below `scan_all`:
```python
@app.command("scan")
def scan(
    name: str = typer.Argument(..., help="Scanner name (see list-scanners)."),
    config: str = typer.Option(None, "--config", help="Path to YAML config file."),
    fmt: str = typer.Option("both", "--format", help="json | html | both"),
    output_dir: str = typer.Option("reports", "--output-dir", help="Report output dir."),
) -> None:
    """Run a single named scanner and write its report."""
    scanners = all_scanners()
    if name not in scanners:
        available = ", ".join(sorted(scanners)) or "none"
        typer.echo(f"Unknown scanner '{name}'. Available: {available}")
        raise typer.Exit(code=1)
    cfg = load_config(config)
    findings = scanners[name]().run(cfg)
    _emit_reports(findings, output_dir, fmt)
```

- [ ] **Step 4: Run the new tests, then the full suite**

Run: `.venv\Scripts\python.exe -m pytest tests/test_cli_scan.py -v`
Expected: PASS (2 passed)

Run: `.venv\Scripts\python.exe -m pytest -q`
Expected: PASS (all Phase 1 + Phase 2 tests, ~34 passed).

- [ ] **Step 5: Smoke-test the real CLI**

Run:
```powershell
.venv\Scripts\sentinel.exe list-scanners
```
Expected: prints `cloudscan` (now registered).

- [ ] **Step 6: Commit**

```bash
git add sentinel/cli.py tests/test_cli_scan.py
git commit -m "feat(cli): add 'scan <name>' command and DRY report helper"
```

---

## Self-Review

**Spec coverage (design spec §4 modules — cloudscan):**
- cloudscan module as a `BaseScanner` (spec §4, §6.2) → Task 4 ✓
- boto3-based AWS inspection (spec §5) → Tasks 1–3 ✓
- Emits shared `Finding` objects (spec §3) → all checks ✓
- Auto-registration so CLI discovers it (spec §6.2 open/closed) → Task 4 ✓
- moto for AWS-mocked tests (spec §5 testing) → Tasks 1–5 ✓
- Defensive / authorized-use positioning (spec §2) → module docstring + note ✓
- CLI per-module `scan <name>` (deferred from core plan) → Task 5 ✓

**Placeholder scan:** No TBD/TODO; every code step contains complete code. ✓

**Type consistency:** `check_public_buckets`, `check_open_security_groups`, `check_users_without_mfa` all share signature `(session) -> list[Finding]` and are called with those exact names in `CloudScanner.run` (Task 4). Rule IDs (`CLOUD-S3-PUBLIC`, `CLOUD-SG-OPEN-INGRESS`, `CLOUD-IAM-NO-MFA`) are identical between check code, tests, and the integration assertion. `_emit_reports(findings, output_dir, fmt)` is defined once and used by both `scan` and `scan-all`. ✓

**Scope / YAGNI:** Three checks only; no pagination handling (accounts in scope are small — add boto3 paginators in a later hardening task if needed), no `Config.ignore_ids` filtering yet (deferred — core already carries the field), no offensive/mutating AWS calls. ✓

## Out of Scope (future tasks)
- boto3 paginators for large accounts (>1000 buckets/users)
- Applying `Config.ignore_ids` to suppress accepted-risk findings
- More checks (public RDS, unencrypted EBS/S3, root access keys, password policy)
- Multi-region security-group scanning (currently the session's default region)

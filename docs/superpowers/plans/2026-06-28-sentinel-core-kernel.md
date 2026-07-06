# Sentinel Core Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `core` kernel of Sentinel — a shared `Finding` model, a `BaseScanner` registry, config loading, JSON/HTML report generation, and a unified Typer CLI — producing a runnable `sentinel` command with zero modules yet.

**Architecture:** A flat `sentinel/` Python package. `core/` holds the shared kernel; every future module will subclass `BaseScanner` (auto-registered) and emit `Finding` objects that `report.py` renders. The CLI discovers scanners from a registry, so adding a module later needs no CLI changes (open/closed).

**Tech Stack:** Python 3.11+, Pydantic v2, Typer, Jinja2, PyYAML, pytest.

---

## File Structure

```
Sentinel/
├─ pyproject.toml                 # package metadata, deps, console script
├─ .gitignore                     # Python ignores
├─ sentinel/
│   ├─ __init__.py
│   ├─ cli.py                     # Typer CLI entrypoint
│   ├─ core/
│   │   ├─ __init__.py
│   │   ├─ finding.py             # Severity enum + Finding model
│   │   ├─ scanner.py             # BaseScanner ABC + registry
│   │   ├─ config.py              # Config model + YAML loader
│   │   └─ report.py             # summarize + write_json + write_html
│   ├─ modules/
│   │   └─ __init__.py            # empty for now; future modules land here
│   └─ templates/
│       └─ report.html.j2         # HTML report template
└─ tests/
    ├─ __init__.py
    ├─ conftest.py                # shared fixtures (sample findings)
    ├─ test_finding.py
    ├─ test_scanner.py
    ├─ test_config.py
    ├─ test_report.py
    └─ test_cli.py
```

The git repo already exists at `Sentinel/` (branch `master`) with the design spec committed. All commands below assume the working directory is the repo root `Sentinel/`.

---

### Task 0: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `sentinel/__init__.py`, `sentinel/core/__init__.py`, `sentinel/modules/__init__.py`
- Create: `tests/__init__.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "sentinel-toolkit"
version = "0.1.0"
description = "Sentinel — a modular defensive security toolkit"
requires-python = ">=3.11"
dependencies = [
    "pydantic>=2.6",
    "typer>=0.12",
    "jinja2>=3.1",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
sentinel = "sentinel.cli:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["sentinel*"]

[tool.setuptools.package-data]
sentinel = ["templates/*.j2"]
```

- [ ] **Step 2: Create `.gitignore`**

```gitignore
__pycache__/
*.py[cod]
.venv/
venv/
*.egg-info/
.pytest_cache/
reports/
node_modules/
.DS_Store
```

- [ ] **Step 3: Create empty package files**

Create these four files, each empty except `sentinel/__init__.py`:

`sentinel/__init__.py`:
```python
__version__ = "0.1.0"
```

`sentinel/core/__init__.py`, `sentinel/modules/__init__.py`, `tests/__init__.py`: empty files.

- [ ] **Step 4: Create and activate a virtual environment, install the package**

Run (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```
Expected: installs pydantic, typer, jinja2, pyyaml, pytest, and the `sentinel` console script without error.

- [ ] **Step 5: Verify pytest runs (collecting zero tests is fine)**

Run: `pytest -q`
Expected: "no tests ran" (exit code 5) — confirms the environment works.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .gitignore sentinel tests
git commit -m "chore: scaffold sentinel package and tooling"
```

---

### Task 1: Finding model + Severity enum

**Files:**
- Create: `sentinel/core/finding.py`
- Test: `tests/test_finding.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_finding.py`:
```python
import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from sentinel.core.finding import Finding, Severity


def _valid_kwargs():
    return dict(
        id="CLOUD-S3-PUBLIC-001",
        module="cloudscan",
        severity=Severity.HIGH,
        title="Public S3 bucket",
        description="Bucket allows public read.",
        remediation="Set the bucket ACL to private.",
    )


def test_finding_created_with_valid_fields():
    f = Finding(**_valid_kwargs())
    assert f.id == "CLOUD-S3-PUBLIC-001"
    assert f.severity is Severity.HIGH
    assert f.evidence == {}          # default
    assert f.resource is None         # default


def test_timestamp_defaults_to_utc_now():
    f = Finding(**_valid_kwargs())
    assert f.timestamp.tzinfo is timezone.utc
    assert isinstance(f.timestamp, datetime)


def test_missing_required_field_raises():
    kwargs = _valid_kwargs()
    del kwargs["remediation"]
    with pytest.raises(ValidationError):
        Finding(**kwargs)


def test_invalid_severity_raises():
    kwargs = _valid_kwargs()
    kwargs["severity"] = "Catastrophic"
    with pytest.raises(ValidationError):
        Finding(**kwargs)


def test_severity_accepts_string_value():
    kwargs = _valid_kwargs()
    kwargs["severity"] = "Critical"
    f = Finding(**kwargs)
    assert f.severity is Severity.CRITICAL


def test_model_dump_json_is_serializable():
    f = Finding(**_valid_kwargs())
    data = f.model_dump(mode="json")
    assert data["severity"] == "High"
    assert isinstance(data["timestamp"], str)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_finding.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.core.finding'`

- [ ] **Step 3: Write minimal implementation**

`sentinel/core/finding.py`:
```python
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Finding(BaseModel):
    id: str
    module: str
    severity: Severity
    title: str
    description: str
    remediation: str
    evidence: dict = Field(default_factory=dict)
    resource: str | None = None
    timestamp: datetime = Field(default_factory=_utcnow)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_finding.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add sentinel/core/finding.py tests/test_finding.py
git commit -m "feat(core): add Finding model and Severity enum"
```

---

### Task 2: BaseScanner ABC + registry

**Files:**
- Create: `sentinel/core/scanner.py`
- Test: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_scanner.py`:
```python
import pytest
from sentinel.core.finding import Finding, Severity
from sentinel.core.scanner import BaseScanner, all_scanners, get_scanner


def test_subclass_with_name_is_registered():
    class DemoScanner(BaseScanner):
        name = "demo"

        def run(self, config):
            return []

    assert "demo" in all_scanners()
    assert get_scanner("demo") is DemoScanner


def test_subclass_without_name_is_not_registered():
    before = set(all_scanners())

    class Nameless(BaseScanner):
        def run(self, config):
            return []

    assert set(all_scanners()) == before


def test_cannot_instantiate_without_run():
    with pytest.raises(TypeError):
        class Broken(BaseScanner):  # missing run
            name = "broken"
        Broken()


def test_run_returns_findings():
    class OneFinding(BaseScanner):
        name = "one"

        def run(self, config):
            return [
                Finding(
                    id="X-1", module="one", severity=Severity.LOW,
                    title="t", description="d", remediation="r",
                )
            ]

    findings = OneFinding().run(config=None)
    assert len(findings) == 1
    assert findings[0].id == "X-1"


def test_all_scanners_returns_copy():
    snapshot = all_scanners()
    snapshot["injected"] = object  # mutate the returned dict
    assert "injected" not in all_scanners()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.core.scanner'`

- [ ] **Step 3: Write minimal implementation**

`sentinel/core/scanner.py`:
```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .finding import Finding

if TYPE_CHECKING:
    from .config import Config

_REGISTRY: dict[str, type["BaseScanner"]] = {}


class BaseScanner(ABC):
    name: str = ""

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "name", ""):
            _REGISTRY[cls.name] = cls

    @abstractmethod
    def run(self, config: "Config") -> list[Finding]:
        ...


def get_scanner(name: str) -> type[BaseScanner]:
    return _REGISTRY[name]


def all_scanners() -> dict[str, type[BaseScanner]]:
    return dict(_REGISTRY)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scanner.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add sentinel/core/scanner.py tests/test_scanner.py
git commit -m "feat(core): add BaseScanner abstract base and registry"
```

---

### Task 3: Config model + YAML loader

**Files:**
- Create: `sentinel/core/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_config.py`:
```python
from sentinel.core.config import Config, load_config


def test_defaults_when_no_path():
    cfg = load_config(None)
    assert cfg.aws_profile is None
    assert cfg.target_url is None
    assert cfg.log_paths == []
    assert cfg.ignore_ids == []
    assert cfg.output_dir == "reports"


def test_load_from_yaml(tmp_path):
    cfg_file = tmp_path / "sentinel.yaml"
    cfg_file.write_text(
        "aws_profile: myacct\n"
        "target_url: https://example.test\n"
        "log_paths:\n"
        "  - /var/log/auth.log\n"
        "ignore_ids:\n"
        "  - CLOUD-S3-PUBLIC-001\n"
        "output_dir: out\n"
    )
    cfg = load_config(cfg_file)
    assert cfg.aws_profile == "myacct"
    assert cfg.target_url == "https://example.test"
    assert cfg.log_paths == ["/var/log/auth.log"]
    assert cfg.ignore_ids == ["CLOUD-S3-PUBLIC-001"]
    assert cfg.output_dir == "out"


def test_empty_yaml_file_yields_defaults(tmp_path):
    cfg_file = tmp_path / "empty.yaml"
    cfg_file.write_text("")
    cfg = load_config(cfg_file)
    assert cfg.output_dir == "reports"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.core.config'`

- [ ] **Step 3: Write minimal implementation**

`sentinel/core/config.py`:
```python
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Config(BaseModel):
    aws_profile: str | None = None
    target_url: str | None = None
    log_paths: list[str] = Field(default_factory=list)
    ignore_ids: list[str] = Field(default_factory=list)
    output_dir: str = "reports"


def load_config(path: str | Path | None = None) -> Config:
    if path is None:
        return Config()
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return Config(**data)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add sentinel/core/config.py tests/test_config.py
git commit -m "feat(core): add Config model and YAML loader"
```

---

### Task 4: Report generation (summarize + JSON + HTML)

**Files:**
- Create: `sentinel/core/report.py`
- Create: `sentinel/templates/report.html.j2`
- Test: `tests/test_report.py`
- Create/modify: `tests/conftest.py`

- [ ] **Step 1: Add a shared fixture**

`tests/conftest.py`:
```python
import pytest
from sentinel.core.finding import Finding, Severity


@pytest.fixture
def sample_findings():
    return [
        Finding(
            id="CLOUD-S3-PUBLIC-001", module="cloudscan", severity=Severity.HIGH,
            title="Public S3 bucket", description="Bucket allows public read.",
            remediation="Set the bucket ACL to private.",
            evidence={"bucket": "my-bucket", "acl": "public-read"},
            resource="my-bucket",
        ),
        Finding(
            id="LOG-BRUTE-001", module="logwatch", severity=Severity.CRITICAL,
            title="Brute-force login detected", description="20 failed logins in 60s.",
            remediation="Lock the account and investigate source IP.",
            evidence={"ip": "10.0.0.5", "attempts": 20},
        ),
        Finding(
            id="WEB-HEADER-001", module="webscan", severity=Severity.LOW,
            title="Missing security header", description="No Content-Security-Policy.",
            remediation="Add a Content-Security-Policy header.",
        ),
    ]
```

- [ ] **Step 2: Write the failing tests**

`tests/test_report.py`:
```python
import json
from sentinel.core.report import summarize, write_json, write_html


def test_summarize_counts_all_severities(sample_findings):
    summary = summarize(sample_findings)
    assert summary == {
        "Critical": 1, "High": 1, "Medium": 0, "Low": 1, "Info": 0
    }


def test_summarize_empty():
    assert summarize([]) == {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    }


def test_write_json_creates_file_with_expected_shape(sample_findings, tmp_path):
    path = write_json(sample_findings, tmp_path)
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["summary"]["Critical"] == 1
    assert len(payload["findings"]) == 3
    assert payload["findings"][0]["id"] == "CLOUD-S3-PUBLIC-001"
    assert "generated_at" in payload


def test_write_html_contains_summary_and_titles(sample_findings, tmp_path):
    path = write_html(sample_findings, tmp_path)
    assert path.exists()
    html = path.read_text(encoding="utf-8")
    assert "Public S3 bucket" in html
    assert "Brute-force login detected" in html
    assert "Critical" in html
    assert "Set the bucket ACL to private." in html


def test_write_json_empty_findings(tmp_path):
    path = write_json([], tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["summary"]["High"] == 0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.core.report'`

- [ ] **Step 4: Create the HTML template**

`sentinel/templates/report.html.j2`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sentinel Report</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
    h1 { margin-bottom: 0.25rem; }
    .meta { color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }
    .summary span { display: inline-block; padding: 0.25rem 0.6rem; margin-right: 0.4rem;
                    border-radius: 4px; font-size: 0.85rem; }
    .Critical { background: #7f1d1d; color: #fff; }
    .High { background: #b91c1c; color: #fff; }
    .Medium { background: #d97706; color: #fff; }
    .Low { background: #ca8a04; color: #fff; }
    .Info { background: #2563eb; color: #fff; }
    .finding { border-left: 4px solid #ccc; padding: 0.5rem 1rem; margin: 0.75rem 0;
               background: #fafafa; }
    .finding.Critical { border-color: #7f1d1d; }
    .finding.High { border-color: #b91c1c; }
    .finding.Medium { border-color: #d97706; }
    .finding.Low { border-color: #ca8a04; }
    .finding.Info { border-color: #2563eb; }
    .rem { color: #065f46; font-size: 0.9rem; }
    code { background: #eee; padding: 0 0.2rem; }
  </style>
</head>
<body>
  <h1>Sentinel Security Report</h1>
  <div class="meta">Generated at {{ generated_at }}</div>
  <div class="summary">
    {% for sev, count in summary.items() %}
      <span class="{{ sev }}">{{ sev }}: {{ count }}</span>
    {% endfor %}
  </div>
  {% for f in findings %}
    <div class="finding {{ f.severity.value }}">
      <strong>[{{ f.severity.value }}] {{ f.title }}</strong>
      <span style="color:#888">({{ f.module }} — {{ f.id }})</span>
      <p>{{ f.description }}</p>
      {% if f.resource %}<p>Resource: <code>{{ f.resource }}</code></p>{% endif %}
      <p class="rem">Fix: {{ f.remediation }}</p>
    </div>
  {% endfor %}
</body>
</html>
```

- [ ] **Step 5: Write minimal implementation**

`sentinel/core/report.py`:
```python
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .finding import Finding, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]
_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {sev.value: counts.get(sev.value, 0) for sev in _SEVERITY_ORDER}


def _timestamped_path(output_dir: str | Path, ext: str, when: datetime) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    return out / f"report-{when.strftime('%Y%m%dT%H%M%S')}.{ext}"


def write_json(findings: list[Finding], output_dir: str | Path) -> Path:
    when = datetime.now(timezone.utc)
    path = _timestamped_path(output_dir, "json", when)
    payload = {
        "generated_at": when.isoformat(),
        "summary": summarize(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_html(findings: list[Finding], output_dir: str | Path) -> Path:
    when = datetime.now(timezone.utc)
    path = _timestamped_path(output_dir, "html", when)
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(
        generated_at=when.isoformat(),
        summary=summarize(findings),
        findings=findings,
    )
    path.write_text(html, encoding="utf-8")
    return path
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_report.py -v`
Expected: PASS (5 passed)

- [ ] **Step 7: Commit**

```bash
git add sentinel/core/report.py sentinel/templates/report.html.j2 tests/test_report.py tests/conftest.py
git commit -m "feat(core): add report generation (summary, JSON, HTML)"
```

---

### Task 5: Unified CLI (Typer)

**Files:**
- Create: `sentinel/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_cli.py`:
```python
import json
from pathlib import Path
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.core.scanner import BaseScanner
from sentinel.core.finding import Finding, Severity

runner = CliRunner()


class _CliDemoScanner(BaseScanner):
    name = "clidemo"

    def run(self, config):
        return [
            Finding(
                id="DEMO-1", module="clidemo", severity=Severity.MEDIUM,
                title="Demo finding", description="d", remediation="r",
            )
        ]


def test_list_scanners_shows_registered():
    result = runner.invoke(app, ["list-scanners"])
    assert result.exit_code == 0
    assert "clidemo" in result.stdout


def test_scan_all_writes_reports_and_reports_count(tmp_path):
    result = runner.invoke(
        app, ["scan-all", "--output-dir", str(tmp_path), "--format", "both"]
    )
    assert result.exit_code == 0
    assert "finding(s)" in result.stdout
    json_files = list(Path(tmp_path).glob("report-*.json"))
    html_files = list(Path(tmp_path).glob("report-*.html"))
    assert len(json_files) == 1
    assert len(html_files) == 1
    payload = json.loads(json_files[0].read_text(encoding="utf-8"))
    # at least the demo finding is present
    ids = [f["id"] for f in payload["findings"]]
    assert "DEMO-1" in ids


def test_scan_all_json_only(tmp_path):
    result = runner.invoke(
        app, ["scan-all", "--output-dir", str(tmp_path), "--format", "json"]
    )
    assert result.exit_code == 0
    assert len(list(Path(tmp_path).glob("report-*.json"))) == 1
    assert len(list(Path(tmp_path).glob("report-*.html"))) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.cli'`

- [ ] **Step 3: Write minimal implementation**

`sentinel/cli.py`:
```python
from __future__ import annotations

import typer

from sentinel import modules  # noqa: F401  (imports register future scanners)
from sentinel.core.config import load_config
from sentinel.core.scanner import all_scanners
from sentinel.core import report as report_mod

app = typer.Typer(
    help="Sentinel — a modular defensive security toolkit (authorized use only).",
    no_args_is_help=True,
)


@app.command("list-scanners")
def list_scanners() -> None:
    """List all registered scanner modules."""
    names = sorted(all_scanners())
    if not names:
        typer.echo("No scanners registered.")
        return
    for name in names:
        typer.echo(name)


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

    if fmt in ("json", "both"):
        typer.echo(f"JSON report: {report_mod.write_json(findings, output_dir)}")
    if fmt in ("html", "both"):
        typer.echo(f"HTML report: {report_mod.write_html(findings, output_dir)}")

    typer.echo(f"Scan complete: {len(findings)} finding(s).")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Run the full suite**

Run: `pytest -q`
Expected: PASS (all tests from Tasks 1–5, ~22 passed)

- [ ] **Step 6: Smoke-test the installed console script**

Run:
```powershell
sentinel list-scanners
sentinel scan-all --output-dir reports --format both
```
Expected: `list-scanners` prints "No scanners registered." (the CLI test's demo scanner is not registered outside pytest); `scan-all` prints "Scan complete: 0 finding(s)." and writes an empty JSON+HTML report into `reports/`.

- [ ] **Step 7: Commit**

```bash
git add sentinel/cli.py tests/test_cli.py
git commit -m "feat(core): add unified Typer CLI (list-scanners, scan-all)"
```

---

## Self-Review

**Spec coverage (core kernel sections of the spec):**
- Finding model (spec §6.1) → Task 1 ✓
- BaseScanner + registry (spec §6.2) → Task 2 ✓
- Config YAML loader (spec §6.4) → Task 3 ✓
- Report JSON + HTML with summary header (spec §6.3) → Task 4 ✓
- CLI (spec §6.5) → Task 5 ✓ (`list-scanners` + `scan-all`; per-module `scan <name>` deferred to the first module plan, since there are no scanners to select yet)
- core tests (spec §6.6) → Tasks 1–5 each ship tests ✓
- Ethical positioning (spec §2) → CLI help string states "authorized use only"; full README banner is part of a later docs task ✓

Deferred by design (not core): cloudscan/logwatch/webscan/netmon modules, dashboard, FastAPI. Each gets its own plan.

**Placeholder scan:** No TBD/TODO; every code step contains complete code. ✓

**Type consistency:** `Finding`, `Severity`, `Config`, `BaseScanner.run(config)`, `all_scanners()`, `get_scanner()`, `summarize()`, `write_json()`, `write_html()` are used with identical signatures across tasks. CLI option is named `fmt` (Python param) exposed as `--format` (Typer alias) — consistent. ✓

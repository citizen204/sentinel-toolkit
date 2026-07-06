# Sentinel — Modular Defensive Security Toolkit — Design Spec

**Date:** 2026-06-28
**Author:** Chilton (Xi) Chen — University of Adelaide, B. IT (Cybersecurity)
**Status:** Approved (design phase)

> Note: The project name "Sentinel" is a working title and may be changed to a
> more unique name before publishing to GitHub (many security products use
> "Sentinel"). Rename before first public push if desired.

## 1. Purpose & Goals

A single, modular, **defensive** security toolkit that showcases breadth across
four cybersecurity domains while remaining one coherent, well-engineered
codebase. Built as a portfolio piece to strengthen a Master of Cybersecurity
application (University of Adelaide) and reinforce ISC2 CC study.

**Why one repo, not four:** depth beats breadth on an application. A single
project with clean architecture, tests, and a real README signals engineering
maturity; four half-finished repos signal scattered effort. This design gives
breadth (four domains) inside one deep artifact.

### Success criteria
- One GitHub repo, coherent architecture, meaningful commit history.
- Four working modules sharing a common `Finding` abstraction.
- Unified CLI + HTML/JSON reports + a Next.js dashboard.
- Tests for the core and each module.
- README documents authorized/defensive use only.

## 2. Ethical / Safety Positioning

All four modules are dual-use security tools and are scoped as **defensive,
authorized-use-only**: scan only your own AWS account, your own web app, and
local lab/test environments. The README states this prominently on the first
screen. This is both responsible and a maturity signal for the application.

## 3. Core Concept — the `Finding` abstraction

The unifying idea: every module, whatever it scans, emits a uniform `Finding`.
Reports and the dashboard consume only `Finding` objects. This is what makes
Sentinel one toolkit rather than four scripts.

```
Finding {
  id, module, severity(Critical/High/Medium/Low/Info),
  title, description, remediation, evidence, resource, timestamp
}
```

## 4. Architecture

```
sentinel/
├─ core/                  # Shared kernel (every module depends on it)
│   ├─ finding.py         # Finding data model (Pydantic)
│   ├─ scanner.py         # BaseScanner abstract interface + registry
│   ├─ report.py          # Generate HTML/JSON reports
│   └─ config.py          # Config loading (YAML + CLI overrides)
├─ modules/
│   ├─ cloudscan/         # AWS misconfiguration scanner (boto3)
│   ├─ logwatch/          # SIEM-lite log analysis / detection
│   ├─ webscan/           # Web vulnerability scanner (requests)
│   └─ netmon/            # Network traffic monitor (scapy)
├─ cli.py                 # Unified CLI entrypoint (Typer)
├─ dashboard/             # Next.js + Tailwind dashboard
└─ tests/                 # pytest
```

### Data flow
```
module scan -> Finding[] -> core aggregates -> report.json + report.html
                                                     -> dashboard reads report.json
```
Dashboard reads a static `report.json` first (simple, sufficient). A FastAPI
layer is only added later if real-time is needed (YAGNI).

## 5. Tech Stack
- **Python 3.11+**: Typer (CLI), Pydantic (models), boto3, requests, scapy, pytest
- **Dashboard**: Next.js + Tailwind CSS
- **Testing**: pytest; `moto` to mock AWS; sample logs/pcap fixtures; local
  vulnerable target for webscan tests

## 6. `core` Kernel Detail

### 6.1 `finding.py`
```python
class Severity(str, Enum):
    CRITICAL = "Critical"; HIGH = "High"; MEDIUM = "Medium"
    LOW = "Low"; INFO = "Info"

class Finding(BaseModel):
    id: str                      # stable id, e.g. "CLOUD-S3-PUBLIC-001"
    module: str                  # "cloudscan" / "logwatch" / ...
    severity: Severity
    title: str
    description: str
    remediation: str             # how to fix — core value of a security tool
    evidence: dict               # e.g. {"bucket": "my-bucket", "acl": "public-read"}
    resource: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
```
`remediation` is deliberately required: a tool that reports problems without
telling you how to fix them is half-done.

### 6.2 `scanner.py`
```python
class BaseScanner(ABC):
    name: str
    @abstractmethod
    def run(self, config: Config) -> list[Finding]: ...
```
A registry lets the CLI discover and dispatch all scanners. Adding a module =
adding a subclass, with no changes to the core (open/closed principle).

### 6.3 `report.py`
Takes `list[Finding]`, outputs:
- **JSON**: `reports/report-<timestamp>.json` (for dashboard/automation)
- **HTML**: Jinja2 template, grouped by severity with a summary count header

### 6.4 `config.py`
YAML file + CLI flag overrides (AWS profile, target URL, log paths, ignore rules).

### 6.5 `cli.py` (Typer)
```bash
sentinel scan cloud --profile myaccount   # single module
sentinel scan all                          # all modules
sentinel report --format html              # generate report
```

### 6.6 core tests
- Finding validation (invalid severity / missing required fields raise)
- Report generation (asserts JSON structure + HTML contains summary counts)
- BaseScanner registry (register/discover works)

## 7. Build Order
1. **core** (Finding + report + CLI skeleton) — the spine
2. **cloudscan** (AWS strength → fastest, most impressive win)
3. **logwatch** (time-series data → feeds the dashboard well)
4. **dashboard v1** (data from steps 2–3 to display)
5. **webscan**
6. **netmon** (scapy needs privileges/setup — fiddliest, last)

## 8. CC Study Alignment
- cloudscan → Access Controls (D3) + Security Operations (D5)
- logwatch → Security Operations (D5) + Incident Response (D2)
- webscan → Network Security (D4)
- netmon → Network Security (D4)
- core/reporting/severity → Security Principles (D1), risk rating

## 9. Out of Scope (for now)
- Real-time streaming / FastAPI backend (only if needed later)
- Authenticated/agent-based scanning
- Any offensive/unauthorized capability

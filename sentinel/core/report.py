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

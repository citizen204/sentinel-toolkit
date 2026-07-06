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

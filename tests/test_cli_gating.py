"""Exit-code gating, so CI can act on both findings and scan health.

Without these, `sentinel scan-all` exits 0 whether it audited an estate cleanly
or never ran at all -- a pipeline gating on the exit code would go green for a
scan that assessed nothing.
"""
from __future__ import annotations

from typer.testing import CliRunner

from sentinel.cli import EXIT_FINDINGS, EXIT_INCOMPLETE, app

runner = CliRunner()


def _invoke(tmp_path, *args, config_body="target_url: https://example.test/\n"):
    cfg = tmp_path / "sentinel.yaml"
    cfg.write_text(config_body, encoding="utf-8")
    return runner.invoke(
        app,
        ["scan-all", "--config", str(cfg), "--include", "webscan",
         "--format", "json", "--output-dir", str(tmp_path), *args],
    )


def test_unconfigured_scanner_exits_zero_without_the_flag(tmp_path):
    """Default behaviour is unchanged; gating is opt-in."""
    result = _invoke(tmp_path, config_body="{}\n")

    assert result.exit_code == 0


def test_unconfigured_scanner_fails_with_fail_on_incomplete(tmp_path):
    """A scan that never ran must be distinguishable from a clean one."""
    result = _invoke(tmp_path, "--fail-on-incomplete", config_body="{}\n")

    assert result.exit_code == EXIT_INCOMPLETE
    assert "Incomplete scan coverage" in result.stdout
    assert "webscan" in result.stdout


def test_fail_on_trips_on_severity(tmp_path):
    import responses

    with responses.RequestsMock() as mock:
        mock.add(responses.GET, "https://example.test/", status=200, headers={})
        result = _invoke(tmp_path, "--fail-on", "Low")

    assert result.exit_code == EXIT_FINDINGS
    assert "at or above Low" in result.stdout


def test_fail_on_ignores_findings_below_the_threshold(tmp_path):
    import responses

    with responses.RequestsMock() as mock:
        mock.add(responses.GET, "https://example.test/", status=200, headers={})
        result = _invoke(tmp_path, "--fail-on", "Critical")

    assert result.exit_code == 0


def test_incomplete_takes_precedence_over_findings(tmp_path):
    """"We could not look" is the more urgent failure, and gets its own code."""
    result = _invoke(
        tmp_path, "--fail-on", "Low", "--fail-on-incomplete", config_body="{}\n"
    )

    assert result.exit_code == EXIT_INCOMPLETE

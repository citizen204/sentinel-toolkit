from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer

from sentinel import modules  # noqa: F401  (imports register future scanners)
from sentinel.core import report as report_mod
from sentinel.core.config import load_config
from sentinel.core.finding import Finding, Severity
from sentinel.core.scanner import all_scanners


class OutputFormat(str, Enum):
    json = "json"
    html = "html"
    both = "both"   # json + html
    sarif = "sarif"
    all = "all"     # json + html + sarif


def run_scanners(scanners, config) -> list[Finding]:
    """Run each scanner, isolating failures.

    If one scanner raises, the others still run and the failure is surfaced as an
    INFO finding rather than crashing the whole scan.
    """
    findings: list[Finding] = []
    for name, scanner_cls in scanners.items():
        try:
            findings.extend(scanner_cls().run(config))
        except Exception as exc:  # noqa: BLE001 - intentionally isolate any scanner failure
            findings.append(
                Finding(
                    id="SCANNER-ERROR",
                    module=name,
                    severity=Severity.INFO,
                    title=f"Scanner '{name}' failed to run",
                    description=f"{type(exc).__name__}: {exc}",
                    remediation="Check this scanner's configuration and credentials.",
                    evidence={"scanner": name, "error": str(exc)},
                    resource=name,
                )
            )
    return findings


def filter_ignored(findings, ignore_ids) -> list[Finding]:
    """Drop findings whose rule id is listed in ignore_ids (accepted risks)."""
    if not ignore_ids:
        return findings
    ignore = set(ignore_ids)
    return [f for f in findings if f.id not in ignore]

app = typer.Typer(
    help="Sentinel — a modular defensive security toolkit (authorized use only).",
    no_args_is_help=True,
)


def _emit_reports(findings, output_dir: str, fmt) -> None:
    fmt = fmt.value if isinstance(fmt, OutputFormat) else fmt
    if fmt in ("json", "both", "all"):
        typer.echo(f"JSON report: {report_mod.write_json(findings, output_dir)}")
    if fmt in ("html", "both", "all"):
        typer.echo(f"HTML report: {report_mod.write_html(findings, output_dir)}")
    if fmt in ("sarif", "all"):
        typer.echo(f"SARIF report: {report_mod.write_sarif(findings, output_dir)}")
    typer.echo(f"Scan complete: {len(findings)} finding(s).")


@app.command("list-scanners")
def list_scanners() -> None:
    """List all registered scanner modules."""
    names = sorted(all_scanners())
    if not names:
        typer.echo("No scanners registered.")
        return
    for name in names:
        typer.echo(name)


def _tokens(value: str | None) -> set[str]:
    return {n.strip() for n in value.split(",") if n.strip()} if value else set()


def _select_scanners(include: str | None, exclude: str | None) -> dict:
    """Filter the registry by --include/--exclude, rejecting unknown scanner names."""
    scanners = all_scanners()
    known = set(scanners)
    unknown = (_tokens(include) | _tokens(exclude)) - known
    if unknown:
        raise ValueError(
            f"Unknown scanner(s): {', '.join(sorted(unknown))}. "
            f"Available: {', '.join(sorted(known)) or 'none'}"
        )
    if include:
        wanted = _tokens(include)
        scanners = {n: c for n, c in scanners.items() if n in wanted}
    if exclude:
        unwanted = _tokens(exclude)
        scanners = {n: c for n, c in scanners.items() if n not in unwanted}
    return scanners


@app.command("scan-all")
def scan_all(
    config: str = typer.Option(None, "--config", help="Path to YAML config file."),
    fmt: OutputFormat = typer.Option(
        OutputFormat.both, "--format", help="json | html | both | sarif | all"
    ),
    output_dir: str = typer.Option(
        None, "--output-dir", help="Report output dir (default: config output_dir)."
    ),
    include: str = typer.Option(
        None, "--include", help="Only run these scanners (comma-separated)."
    ),
    exclude: str = typer.Option(
        None, "--exclude", help="Skip these scanners (comma-separated), e.g. cloudscan."
    ),
) -> None:
    """Run every registered scanner and write a consolidated report.

    A failure in one scanner does not stop the others (see run_scanners).
    Use --include/--exclude to narrow which scanners run.
    """
    cfg = load_config(config)
    try:
        selected = _select_scanners(include, exclude)
    except ValueError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=1)
    findings = run_scanners(selected, cfg)
    findings = filter_ignored(findings, cfg.ignore_ids)
    _emit_reports(findings, output_dir or cfg.output_dir, fmt)


@app.command("scan")
def scan(
    name: str = typer.Argument(..., help="Scanner name (see list-scanners)."),
    config: str = typer.Option(None, "--config", help="Path to YAML config file."),
    fmt: OutputFormat = typer.Option(
        OutputFormat.both, "--format", help="json | html | both | sarif | all"
    ),
    output_dir: str = typer.Option(
        None, "--output-dir", help="Report output dir (default: config output_dir)."
    ),
) -> None:
    """Run a single named scanner and write its report."""
    scanners = all_scanners()
    if name not in scanners:
        available = ", ".join(sorted(scanners)) or "none"
        typer.echo(f"Unknown scanner '{name}'. Available: {available}")
        raise typer.Exit(code=1)
    cfg = load_config(config)
    findings = scanners[name]().run(cfg)
    findings = filter_ignored(findings, cfg.ignore_ids)
    _emit_reports(findings, output_dir or cfg.output_dir, fmt)


_SAMPLE_CONFIG = """\
# Sentinel configuration — point each scanner at real targets.
aws_profile: my-audit-profile          # cloudscan: AWS profile to audit
aws_regions:                           # cloudscan: regions to scan (empty = default region)
  - us-east-1
target_url: https://app.example.com    # webscan: URL to check
log_paths:                             # logwatch: auth logs to analyse
  - /var/log/auth.log
capture_file: capture.pcap             # netmon: a flow log or a .pcap/.pcapng
ignore_ids: []                         # suppress accepted-risk findings by rule id
output_dir: reports
"""


@app.command("init-config")
def init_config(
    path: str = typer.Option("sentinel.yaml", "--path", help="Where to write the config."),
    force: bool = typer.Option(False, "--force", help="Overwrite if it already exists."),
) -> None:
    """Write a sample configuration file to get started."""
    target = Path(path)
    if target.exists() and not force:
        typer.echo(f"{target} already exists. Use --force to overwrite.")
        raise typer.Exit(code=1)
    target.write_text(_SAMPLE_CONFIG, encoding="utf-8")
    typer.echo(f"Wrote sample config to {target}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

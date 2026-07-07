from __future__ import annotations

import typer

from sentinel import modules  # noqa: F401  (imports register future scanners)
from sentinel.core.config import load_config
from sentinel.core.finding import Finding, Severity
from sentinel.core.scanner import all_scanners
from sentinel.core import report as report_mod


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

app = typer.Typer(
    help="Sentinel — a modular defensive security toolkit (authorized use only).",
    no_args_is_help=True,
)


def _emit_reports(findings, output_dir: str, fmt: str) -> None:
    if fmt in ("json", "both"):
        typer.echo(f"JSON report: {report_mod.write_json(findings, output_dir)}")
    if fmt in ("html", "both"):
        typer.echo(f"HTML report: {report_mod.write_html(findings, output_dir)}")
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


@app.command("scan-all")
def scan_all(
    config: str = typer.Option(None, "--config", help="Path to YAML config file."),
    fmt: str = typer.Option("both", "--format", help="json | html | both"),
    output_dir: str = typer.Option("reports", "--output-dir", help="Report output dir."),
) -> None:
    """Run every registered scanner and write a consolidated report.

    A failure in one scanner does not stop the others (see run_scanners).
    """
    cfg = load_config(config)
    findings = run_scanners(all_scanners(), cfg)
    _emit_reports(findings, output_dir, fmt)


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


def main() -> None:
    app()


if __name__ == "__main__":
    main()

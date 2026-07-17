from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer

from sentinel import modules  # noqa: F401  (imports register future scanners)
from sentinel.core import report as report_mod
from sentinel.core.config import load_config
from sentinel.core.finding import Finding, Severity
from sentinel.core.rule import apply_rule_config
from sentinel.core.scanner import all_scanners
from sentinel.core.suppression import apply_suppressions


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


def _is_error_finding(rule_id: str) -> bool:
    """Error findings (scanner/check failures) end in -ERROR and are protected."""
    return rule_id.endswith("-ERROR")


def filter_ignored(findings, ignore_ids) -> list[Finding]:
    """Drop findings whose rule id is listed in ignore_ids.

    DEPRECATED in favour of `suppressions`, which keep an audit trail. Error
    findings can never be ignored — hiding a failed scan is worse than noise.
    """
    if not ignore_ids:
        return findings
    ignore = set(ignore_ids)
    return [
        f for f in findings if f.id not in ignore or _is_error_finding(f.id)
    ]

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
    suppressed = report_mod.count_suppressed(findings)
    total = len(findings)
    note = f" ({suppressed} suppressed)" if suppressed else ""
    typer.echo(f"Scan complete: {total} finding(s){note}.")


def unknown_rule_ids(cfg) -> list[str]:
    """Rule ids referenced by config that don't exist in the catalog."""
    from sentinel.core.rule import RULES

    referenced = set(cfg.rules) | set(cfg.ignore_ids)
    referenced |= {s.rule for s in cfg.suppressions if s.rule}
    return sorted(referenced - set(RULES))


def _load_validated_config(path):
    """Load config and reject references to rules that don't exist.

    A typo'd rule id would otherwise mean the override, ignore, or suppression
    silently never applies — the scan looks configured but isn't.
    """
    cfg = load_config(path)
    unknown = unknown_rule_ids(cfg)
    if unknown:
        typer.echo(
            f"Unknown rule id(s) in config: {', '.join(unknown)}. "
            f"Run 'sentinel rules' to see the catalog."
        )
        raise typer.Exit(code=1)
    for rule_id in cfg.ignore_ids:
        if _is_error_finding(rule_id):
            typer.echo(
                f"Warning: '{rule_id}' cannot be ignored — scan failures are always reported."
            )
    return cfg


@app.command("list-scanners")
def list_scanners() -> None:
    """List all registered scanner modules."""
    names = sorted(all_scanners())
    if not names:
        typer.echo("No scanners registered.")
        return
    for name in names:
        typer.echo(name)


@app.command("rules")
def rules() -> None:
    """List the rule catalog (id, severity, category, title)."""
    from sentinel.core.rule import RULES
    if not RULES:
        typer.echo("No rules registered.")
        return
    for rid in sorted(RULES):
        r = RULES[rid]
        typer.echo(f"{r.id}  [{r.severity.value}/{r.category}]  {r.title}")


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
    cfg = _load_validated_config(config)
    try:
        selected = _select_scanners(include, exclude)
    except ValueError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=1)
    findings = run_scanners(selected, cfg)
    findings = apply_rule_config(findings, cfg)
    findings = filter_ignored(findings, cfg.ignore_ids)
    findings = apply_suppressions(findings, cfg.suppressions)
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
    cfg = _load_validated_config(config)
    findings = scanners[name]().run(cfg)
    findings = apply_rule_config(findings, cfg)
    findings = filter_ignored(findings, cfg.ignore_ids)
    findings = apply_suppressions(findings, cfg.suppressions)
    _emit_reports(findings, output_dir or cfg.output_dir, fmt)


_SAMPLE_CONFIG = """\
# Sentinel configuration — point each scanner at real targets.
aws_profile: my-audit-profile          # cloudscan: AWS profile to audit
aws_regions: []                        # cloudscan: empty = scan every region enabled for
                                       # the account (ec2:DescribeRegions). Pin a list to
                                       # narrow the scope, e.g. [us-east-1, ap-southeast-2]
# Audit many accounts by assuming a role in each (omit to audit the current creds).
# Your principal needs sts:AssumeRole on each role; each role carries the read-only
# audit policy from docs/aws-iam-policy.json.
# aws_accounts:
#   - role_arn: arn:aws:iam::111111111111:role/SentinelAudit
#     regions: [us-east-1, ap-southeast-2]
#   - role_arn: arn:aws:iam::222222222222:role/SentinelAudit
target_url: https://app.example.com    # webscan: URL to check
log_paths:                             # logwatch: auth logs to analyse
  - /var/log/auth.log
capture_file: capture.pcap             # netmon: a flow log or a .pcap/.pcapng
ignore_ids: []                         # DEPRECATED — prefer suppressions below.
                                       # Error findings can never be ignored.
suppressions:                          # accepted risks: kept in the report, marked suppressed
  # narrow by any of: dedupe_key / rule / resource / account_id / region /
  # asset_type / provider. At least one is required (a criteria-less
  # suppression matches nothing rather than hiding the whole report).
  - rule: CLOUD-IAM-NO-MFA
    resource: deploy-bot
    account_id: "123456789012"         # pin to one account so it can't match elsewhere
    reason: service account, MFA not applicable
    created_by: chilton
    ticket: SEC-123
    expires: 2027-01-01                # optional; suppression lapses after this date
profile: baseline                      # baseline = high-confidence, high-risk rules only;
                                       # strict = also noisier/compliance-oriented rules
rules:                                 # per-rule overrides
  LOG-BRUTEFORCE:
    threshold: 10                      # tune threshold-based rules to your environment
  CLOUD-S3-NO-VERSIONING:
    enabled: false                     # turn a rule off entirely
  CLOUD-IAM-NO-MFA:
    severity: High                     # re-rate for your own risk model
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


@app.command("diff")
def diff(
    old: str = typer.Argument(..., help="Path to the older report.json."),
    new: str = typer.Argument(..., help="Path to the newer report.json."),
) -> None:
    """Compare two JSON reports: new, resolved, and persisting findings."""
    import json

    from sentinel.core.diff import diff_reports

    old_report = json.loads(Path(old).read_text(encoding="utf-8"))
    new_report = json.loads(Path(new).read_text(encoding="utf-8"))
    result = diff_reports(old_report, new_report)

    typer.echo(f"New:        {len(result['new'])}")
    typer.echo(f"Resolved:   {len(result['resolved'])}")
    typer.echo(f"Persisting: {len(result['persisting'])}")
    for f in result["new"]:
        typer.echo(f"  + [{f.get('severity')}] {f.get('id')}  {f.get('resource', '')}")
    for f in result["resolved"]:
        typer.echo(f"  - [{f.get('severity')}] {f.get('id')}  {f.get('resource', '')}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

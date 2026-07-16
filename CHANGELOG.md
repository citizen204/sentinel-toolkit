# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Professional suppressions: accept risks by rule/resource with a reason and optional expiry;
  suppressed findings are kept in reports (SARIF `suppressions`, HTML/dashboard markers) and
  counted separately instead of being silently dropped.
- `sentinel diff <old.json> <new.json>` — new / resolved / persisting findings across scans,
  matched by stable `dedupe_key`.

### Fixed
- **S3 encryption check no longer swallows unexpected AWS errors.** `AccessDenied` and similar
  now surface as `CLOUD-CHECK-ERROR` instead of silently reporting a clean bucket (false negative).
- **EBS and RDS checks now paginate**, so large accounts are scanned past the first page.
- **S3 Block Public Access considers account-level BPA**, removing false positives on accounts
  that block centrally; evidence records bucket/account/effective posture.

### Changed
- `CLOUD-IAM-ADMIN-POLICY` is explicitly scoped to *direct* user attachment (group/role/inline
  and wildcard customer-managed policies need effective-privilege analysis, not yet implemented).

## [0.1.0] - 2026-07-08

### Added
- Modular scanner core: `Finding` and `Asset` models, `BaseScanner` auto-registration,
  and a central `Rule` catalog with a `build_finding` factory.
- Scanners:
  - `cloudscan` — 10 AWS checks: S3 (public ACL, encryption, versioning, Block Public Access),
    security groups open to `0.0.0.0/0` / `::/0` (all regions), IAM (no MFA, no password policy,
    AdministratorAccess), and EBS/RDS encryption at rest.
  - `logwatch` — SSH brute-force and direct privileged logins.
  - `webscan` — missing HTTP security headers.
  - `netmon` — port-scan and host-sweep detection from a flow log or scapy pcap/live capture.
- Unified reporting: JSON, HTML, and SARIF 2.1.0 with stable `partialFingerprints`.
- Typer CLI: `scan`, `scan-all`, `list-scanners`, `rules`, `init-config`, with
  `--include/--exclude`, a validated `--format`, and config `ignore_ids`.
- Next.js + Tailwind dashboard: severity summary, filtering, drag-and-drop upload, asset display.
- CI (pytest + ruff + dashboard eslint/build), CodeQL, and Dependabot.

[Unreleased]: https://github.com/citizen204/sentinel-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/citizen204/sentinel-toolkit/releases/tag/v0.1.0

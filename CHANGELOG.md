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

- **Scan context**: `ScanContext(account_id, partition, regions, started_at, tool_version)` is
  established up front via STS `GetCallerIdentity`, and every AWS asset is now attributed to its
  account. `dedupe_key` includes the account, so the same resource id in two accounts no longer
  collides.
- **Audit-grade evidence**: every finding now carries `api` (the call it came from), `rationale`
  (why the observed state is a failure), and `verify` (how to confirm the fix), alongside the raw
  `evidence` fields and the account/region on its asset. Surfaced in JSON, HTML, SARIF
  (message + properties), and the dashboard. A failed check states that its result is unknown —
  explicitly not a pass. Tests guard that every rule in every module ships this trail.
- **Per-rule configuration and profiles**: `profile: baseline | strict` plus per-rule
  `enabled` / `severity` / `threshold` overrides. Error findings (scanner/check failures) are
  never filtered by config. `Rule` gains a `compliance` field as the hook for a future,
  verified control mapping.
- **Multi-account auditing**: configure `aws_accounts: [{role_arn, regions}]` and Sentinel
  assumes each role in turn (`sts:AssumeRole`), attributing findings to each account. An
  unreachable account is reported as a finding; the remaining accounts still get scanned.
- **Precise suppressions**: narrow by `dedupe_key`, `rule`, `resource`, `account_id`, `region`,
  `asset_type`, or `provider`, with a `created_by` / `created_at` / `ticket` audit trail. A
  criteria-less suppression now matches nothing instead of hiding the whole report.

- **Automatic region discovery**: with no `aws_regions` configured, cloudscan now scans every
  region enabled for the account (`ec2:DescribeRegions`) instead of only the session default,
  so "all regions" is literally true. Pin a list to narrow the scope.
- **Config that doesn't apply is now an error**: `profile` is a validated enum (a typo is
  rejected instead of silently falling back to baseline), and unknown rule ids in `rules`,
  `ignore_ids`, or `suppressions` abort the run with a clear message.
- **Profile tiers now mean something**: `baseline` carries high-confidence, high-risk rules;
  `strict` adds the noisier/compliance-oriented ones (starting with S3 versioning).

### Fixed
- **`s3control` is called with an explicit region.** Account-level Block Public Access would
  raise `NoRegionError` on a session without a default region; the region is now resolved from
  the scan scope and recorded in the finding's evidence.
- **`ignore_ids` can no longer hide scan failures.** Any `*-ERROR` finding survives ignore rules,
  and `ignore_ids` is deprecated in favour of `suppressions` (which carry reason/ticket/expiry).
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

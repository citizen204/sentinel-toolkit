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

- **IAM effective-privilege analysis** (`CLOUD-IAM-EFFECTIVE-ADMIN`): resolves every path that
  reaches a user — managed and inline policies, directly or inherited via groups — and flags
  `Action: "*"` on `Resource: "*"`, naming the path in the evidence. Supersedes
  `CLOUD-IAM-ADMIN-POLICY`, which only saw `AdministratorAccess` attached directly. Escalation
  chains, permission boundaries, and SCPs are documented as not-yet-evaluated.
- **Supply-chain hardening**: the container runs as a non-root user (uid 10001) and pins its
  base image by digest; a new workflow builds the image, asserts it isn't root, generates a
  CycloneDX SBOM, and scans it with Trivy into the Security tab. Dependabot now tracks the
  base image too.
- **Automatic region discovery**: with no `aws_regions` configured, cloudscan now scans every
  region enabled for the account (`ec2:DescribeRegions`) instead of only the session default,
  so "all regions" is literally true. Pin a list to narrow the scope.
- **Config that doesn't apply is now an error**: `profile` is a validated enum (a typo is
  rejected instead of silently falling back to baseline), and unknown rule ids in `rules`,
  `ignore_ids`, or `suppressions` abort the run with a clear message.
- **Profile tiers now mean something**: `baseline` carries high-confidence, high-risk rules;
  `strict` adds the noisier/compliance-oriented ones (starting with S3 versioning).

- **CIS AWS Benchmark mapping**: rules that correspond to a CIS control now carry its id
  (`compliance`), findings inherit it, `sentinel rules` prints it, and `profile: cis` runs only
  mapped rules. Every id is traced to AWS Security Hub's published control table — 4 of 16 cloud
  rules qualified. `docs/compliance.md` records the mapping, the rules that deliberately went
  unmapped and why, and the benchmark controls Sentinel doesn't cover; tests pin the table so it
  can't drift.
- **Dashboard posture tracker**: load several runs and get *since the previous run*
  (new/resolved/persisting, matched on the same `dedupe_key` as `sentinel diff`), an open-findings
  trend per run, and by-module/account/region rollups. Runs sort by `generated_at`, so drop order
  doesn't matter. Suppressed findings are excluded from trend and rollups — an accepted risk isn't
  an open one.

- **Scan coverage travels with the report** (`ReportEnvelope` v1): every JSON report now
  carries `schema_version`, `run_id`, `tool_version`, `ruleset_digest`, `config_digest`, and a
  `coverage` block recording each scanner's outcome plus the accounts, regions, and rules the
  run actually assessed.
- **`sentinel diff` gained an `unassessed` bucket.** A finding missing from the newer run is
  reported as resolved *only* if that run covered its scanner, rule, account, and region;
  otherwise its status is unknown. The dashboard shows the same bucket, computed the same way.
- **A scanner with no input now says so** (`SCANNER-SKIPPED`) instead of returning an empty
  list, and a partially-readable log set reports the files it could not read
  (`LOG-SOURCE-ERROR`). Neither can be filtered away by `ignore_ids`.
- **Customer managed policy admin check** (`CLOUD-IAM-CUSTOM-POLICY-ADMIN`) and **strict S3 BPA
  check** (`CLOUD-S3-BPA-NOT-STRICT`), which evaluate what AWS IAM.1 and CIS 2.1.4 actually
  evaluate. See "Fixed" below for why the previous mappings were wrong.
- **Supply-chain gating with teeth**: every GitHub Action is pinned to a full commit SHA and
  Syft/Trivy to image digests; fixable CRITICAL/HIGH vulnerabilities in *application*
  dependencies now fail the build, while unfixable base-image CVEs continue to report into the
  Security tab. A new `requirements.lock` constrains the image build, and CI fails if the built
  image drifts from it.

### Fixed
- **Security groups no longer miss the worst rule there is.** `IpProtocol: -1` (all protocols,
  all ports) carries no port range, so a range-only check returned *nothing* for a group open
  to the entire internet. Protocol is now handled explicitly: `-1` is reported as all-ports
  exposure in its own right, and UDP on port 22 is no longer labelled "SSH".
- **IAM admin detection no longer trusts a policy's name.** A customer managed policy called
  `AdministratorAccess` that grants only `s3:GetObject` was reported as admin without its
  document ever being read; only the AWS-managed ARN is now trusted by identity. All five IAM
  list calls paginate, so admin paths past the first page are no longer invisible, and policy
  documents are cached across users.
- **Config typos are rejected instead of ignored.** `aws_regons`, `threhsold`, and `reson`
  parsed happily and did nothing; every config model is now `extra="forbid"`.
- **CIS mappings corrected.** `CLOUD-IAM-EFFECTIVE-ADMIN` was mapped to CIS 1.16 / AWS IAM.1,
  which evaluates *customer managed policies only* — explicitly not the inline and AWS-managed
  paths that rule follows. `CLOUD-S3-NO-BPA` was mapped to CIS 2.1.4, which Security Hub splits
  into S3.1 (account) **and** S3.8 (bucket), both required; that rule passes on either. Both ids
  were real and correctly transcribed — the mappings were still wrong, because the rules didn't
  test what the controls test. Both are now unmapped, with mapped counterparts alongside them
  and the reasoning recorded in `docs/compliance.md`.
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

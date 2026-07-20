# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-07-20

0.2.0 shipped a coverage model that was supposed to make "resolved" mean something.
Review found four ways it still did not. No new rules in this release.

### Fixed
- **0.1.x reports can actually be read.** `diff` validated 1.x coverage against the 2.0
  model and raised, on every one of them, while the 0.2.0 changelog claimed they were
  readable. They are now read and explicitly distrusted: comparison proceeds, warnings
  explain why, and nothing in a cross-schema comparison is reported as resolved —
  `dedupe_key` derives partly from a rule's title, 0.2.0 renamed rules, and "gone" is
  therefore indistinguishable from "renamed". A real 1.x report now lives in
  `tests/fixtures/` so this is tested rather than claimed.
- **Three ways a broken scan reported itself as complete.** A failed `sts:GetCallerIdentity`,
  a failed region discovery, and an account that could not be assumed into all produced
  findings but no `ERROR` coverage, so `--fail-on-incomplete` exited 0. Each now records an
  explicit error scope; the unreachable account is attributed by parsing its role ARN, since
  STS never answered to supply the id.
- **The completeness gate judged scanners nobody asked to run.** `--include webscan
  --fail-on-incomplete` exited 3 even when webscan succeeded, because excluded scanners were
  marked skipped and the gate checked every registered scanner. Excluded scanners are still
  recorded in the report — a later diff needs to know they were not assessed — but the gate
  now judges only the selection.
- **The documented IAM policy no longer lags the code.** It was missing
  `iam:ListEntitiesForPolicy`, added in 0.2.0 for the permissions-boundary exclusion, so
  following the README produced AccessDenied on a real account. Permissions now live in a
  machine-readable manifest (`cloudscan/permissions.py`) that tests check in both directions:
  every action the code calls is granted, and every granted action has a caller. The policy
  is also validated for shape, since an unknown key makes AWS reject the whole document.
- **`config_digest` includes `aws_profile`.** Two scans of different accounts hashed
  identically, so a diff across them showed no configuration change.

### Added
- `sentinel scan <name>` accepts `--fail-on` and `--fail-on-incomplete`, which previously
  only `scan-all` had.

### Known limitations
- Coverage granularity is per (scanner, account, region), not per rule. One failing IAM check
  therefore leaves successful S3 rules in the same account unconfirmable. This is deliberately
  conservative and will produce persistent `unassessed` entries on large estates; a
  rule-to-check mapping is planned for 0.3.

## [0.2.0] - 2026-07-19 — Trust kernel

Everything in this release exists to make one claim defensible: **when Sentinel says
a finding is resolved, it looked.** Two of the fixes below close holes introduced by
0.1.0's own coverage work.

### Fixed
- **Empty coverage no longer means "everything covered".** Coverage was inferred from
  the findings a run produced, so a clean account produced empty account/region lists —
  and `covered()` read empty as "unconstrained". The cleanest possible scan therefore
  made the strongest possible claim, retiring findings from accounts it never touched.
  Coverage is now **recorded during execution** as `CoverageUnit(scanner, account,
  region, check, status)`, and absence of a unit means nothing was proven.
- **Coverage no longer cross-multiplies scopes.** Flat `accounts × regions` lists claimed
  four scopes when two were scanned; units are concrete tuples.
- **A fully unprotected S3 bucket is visible under `profile: cis` again.** The strict BPA
  check skipped buckets with no protection at either level, deferring to
  `CLOUD-S3-NO-BPA` — which the same release had unmapped from CIS. Individually
  reasonable, jointly a blind spot over the worst possible bucket. The compliance rule
  now stands on its own, and an end-to-end profile test covers the composed pipeline
  rather than each check in isolation.
- **`ListBuckets` is paginated.** AWS rejects unpaginated calls for accounts above the
  10,000-bucket quota.
- **IAM.1 now excludes permissions boundary policies**, matching the control's
  `excludePermissionBoundaryPolicy: true`. The last known deviation in that mapping.

### Added
- **Per-scope coverage granularity.** One account failing to assume no longer prevents
  every other account's findings from being confirmed as resolved; one failed check
  marks only its own scope unknown.
- **`--fail-on <severity>` and `--fail-on-incomplete`** with distinct exit codes (2 and
  3), so CI can tell "we found problems" from "we could not look". Both are opt-in.
- **Scan health in every format.** HTML leads with a coverage banner; SARIF records
  `invocations[].executionSuccessful` plus `toolExecutionNotifications`, so a consumer
  seeing zero results can distinguish clean from broken.
- **Named dropped scopes** in `sentinel diff` warnings — which account or region stopped
  being scanned, not just how many findings went unassessed.
- **One shared S3 inventory per account.** Five checks each re-enumerated every bucket
  and account-level BPA was fetched twice.
- **Rule `revision` and build provenance.** The ruleset digest now covers detection logic,
  not just metadata — previously, tightening a check left the digest unchanged and a diff
  blamed the estate. Reports carry `build_commit` (from git or `SENTINEL_BUILD_COMMIT`),
  and the package is no longer pinned at 0.1.0.

### Changed
- **Report `schema_version` is now 2.0.** `coverage.scanners/accounts/regions` are
  replaced by `coverage.units`. ~~Reports written by 0.1.x are still readable; the diff
  treats them as unable to confirm resolution.~~
  **Correction (0.2.1): this was not true when written.** `diff` validated 1.x coverage
  against the 2.0 model and raised a `ValidationError` on every 0.1.x report. The claim was
  never tested. Fixed in 0.2.1; a 1.x fixture is now in the test suite so the claim is
  verified rather than asserted.

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

[Unreleased]: https://github.com/citizen204/sentinel-toolkit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/citizen204/sentinel-toolkit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/citizen204/sentinel-toolkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/citizen204/sentinel-toolkit/releases/tag/v0.1.0

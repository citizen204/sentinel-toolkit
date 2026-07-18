# Compliance mapping

Sentinel maps a rule to a benchmark control **only when the rule checks the same thing the
control requires**. Everything else is listed as an explicit gap. A wrong control number is
worse than no control number: it lets someone claim compliance they don't have.

**Source of truth:** the control-to-requirement mapping published by AWS Security Hub,
[CIS AWS Foundations Benchmark in Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html),
which lists each control's requirement number per benchmark version. Mappings below were taken
from that table, not from memory.

Run only the mapped rules with:

```bash
sentinel scan-all --config sentinel.yaml   # with: profile: cis
```

## Mapped

| Sentinel rule | Control | Benchmark requirement | Basis |
|---|---|---|---|
| `CLOUD-SG-OPEN-INGRESS` | EC2.53 / EC2.54 | **CIS-AWS-3.0.0: 5.2** (IPv4) and **5.3** (IPv6) | The rule flags `0.0.0.0/0` **and** `::/0` to remote administration ports (22/3389), which is exactly what the two requirements split on. |
| `CLOUD-S3-BPA-NOT-STRICT` | S3.1 **and** S3.8 | **CIS-AWS-3.0.0: 2.1.4** | Security Hub decomposes 2.1.4 into an account-level control (S3.1) and a bucket-level one (S3.8). Both must pass, so the mapped rule requires both levels. |
| `CLOUD-RDS-UNENCRYPTED` | RDS.3 | **CIS-AWS-3.0.0: 2.3.1** | The rule reads `StorageEncrypted` per DB instance — the same property the control checks. |
| `CLOUD-IAM-CUSTOM-POLICY-ADMIN` | IAM.1 | **CIS-AWS-1.4.0: 1.16** | IAM.1 evaluates the default version of **customer managed policies**, attached or not. This rule calls `ListPolicies(Scope=Local)` and reads each default version — the same population, the same test. CIS removed the requirement in v3.0.0, so it maps to v1.4.0. |

### Risk rules vs. compliance rules

Two pairs of rules look like duplicates and are not. In each pair the first answers *"is this
dangerous?"* and the second answers *"does this satisfy the control as written?"* — different
populations, different verdicts.

| Risk rule (unmapped) | Compliance rule (mapped) | Where they disagree |
|---|---|---|
| `CLOUD-S3-NO-BPA` | `CLOUD-S3-BPA-NOT-STRICT` | Account-level BPA really does protect a bucket, so the risk rule passes it. CIS 2.1.4 still fails it, because S3.8 (bucket level) is unset. |
| `CLOUD-IAM-EFFECTIVE-ADMIN` | `CLOUD-IAM-CUSTOM-POLICY-ADMIN` | The risk rule follows inline, AWS-managed, and group paths to a *user*. IAM.1 ignores all of those and evaluates customer managed *policies*, attached or not. |

Merging either pair would mean asserting a control id over a check that doesn't establish it.

## A correction, kept on the record

Earlier versions mapped `CLOUD-IAM-EFFECTIVE-ADMIN` to CIS 1.16 and `CLOUD-S3-NO-BPA` to 2.1.4.
Both control ids were real and correctly transcribed from the AWS table — but both mappings were
wrong, because the rules didn't evaluate what the controls evaluate:

- **IAM.1** states plainly: *"The control only checks the customer managed policies that you
  create. It does not check inline and AWS managed policies."* The rule checked precisely those,
  and required attachment to a user, which IAM.1 does not.
- **2.1.4** is satisfied only when S3.1 **and** S3.8 pass. The rule passed a bucket when *either*
  level was set.

The failure mode is worth naming, because it survives the obvious review: the ids were verified
against the source, so anyone spot-checking them would find them correct. What wasn't checked was
the **audit procedure** behind each id. Matching on a control's title or theme produces mappings
that look rigorous and aren't. Every entry in the table above now cites the population and
property the control actually tests.

## Not mapped — and why

These rules are useful but do **not** currently satisfy a control as written, so they carry no
mapping and are excluded from the `cis` profile.

| Sentinel rule | Why not mapped |
|---|---|
| `CLOUD-S3-NO-ENCRYPTION` | In CIS v3.0.0, requirement **2.1.1 is "require requests to use SSL"** (in-transit), not bucket encryption at rest. There is no at-rest S3 bucket-encryption requirement in the published v3.0.0 mapping, so this rule stays unmapped. |
| `CLOUD-EBS-UNENCRYPTED` | Requirement 2.2.1 (control EC2.7) is **"EBS *default* encryption should be enabled"** — an account-level setting. This rule inspects individual volumes instead, which is a different (complementary) check. |
| `CLOUD-IAM-NO-MFA` | CIS 1.10 scopes to **IAM users that have a console password**. This rule flags any user without an MFA device, including programmatic-only service accounts, so it is broader than the control. Aligning it needs a login-profile check. |
| `CLOUD-IAM-NO-PASSWORD-POLICY` | CIS 1.8 / 1.9 require a **minimum length of 14** and **password reuse prevention**. This rule only detects the total absence of a policy; it does not evaluate those parameters. |
| `CLOUD-S3-PUBLIC` | Closest requirement (2.1.4) is about Block Public Access being enabled, not about detecting a public ACL. Related in intent, not the same check. |
| `CLOUD-S3-NO-BPA` | Passes a bucket when *either* bucket- or account-level BPA is set. That is the right answer for exposure and the wrong one for 2.1.4, which needs both. See `CLOUD-S3-BPA-NOT-STRICT`. |
| `CLOUD-IAM-EFFECTIVE-ADMIN` | Evaluates paths reaching an IAM user, including inline and AWS managed policies — explicitly outside IAM.1's scope. See `CLOUD-IAM-CUSTOM-POLICY-ADMIN`. |
| `CLOUD-S3-NO-VERSIONING`, all `logwatch` / `webscan` / `netmon` rules | No corresponding CIS AWS Foundations requirement. |

## Known deviations within mapped rules

Even where a mapping holds, the implementation isn't identical to Security Hub's:

| Rule | Deviation |
|---|---|
| `CLOUD-IAM-CUSTOM-POLICY-ADMIN` | IAM.1 sets `excludePermissionBoundaryPolicy: true`. Sentinel does not yet detect which policies are in use as permission boundaries, so a boundary policy granting `*`/`*` would be reported where Security Hub would exclude it. |
| `CLOUD-IAM-EFFECTIVE-ADMIN` | Policy `Condition` blocks, permission boundaries, and SCPs are not evaluated, so a constrained grant is still reported. The rule is titled "potential unrestricted admin grant" for that reason. |

## Known gaps in benchmark coverage

Sentinel implements a fraction of the benchmark. It is **not** a CIS assessment tool. Large
areas — CloudTrail, AWS Config, CloudWatch alarms, KMS rotation, root-user controls, access-key
rotation, IMDSv2, VPC flow logs — are not implemented at all. The `cis` profile runs the mapped
rules only; passing it says nothing about the requirements Sentinel never checks.

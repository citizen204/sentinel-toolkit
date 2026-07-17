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
| `CLOUD-S3-NO-BPA` | S3.1 / S3.8 | **CIS-AWS-3.0.0: 2.1.4** | The rule requires all four Block Public Access settings, at bucket or account level. |
| `CLOUD-RDS-UNENCRYPTED` | RDS.3 | **CIS-AWS-3.0.0: 2.3.1** | The rule reads `StorageEncrypted` per DB instance — the same property the control checks. |
| `CLOUD-IAM-EFFECTIVE-ADMIN` | IAM.1 | **CIS-AWS-1.4.0: 1.16** | "IAM policies should not allow full `*` administrative privileges." CIS **removed** this requirement in v3.0.0, so it is mapped to v1.4.0 rather than invented for v3.0.0. |

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
| `CLOUD-S3-NO-VERSIONING`, all `logwatch` / `webscan` / `netmon` rules | No corresponding CIS AWS Foundations requirement. |

## Known gaps in benchmark coverage

Sentinel implements a fraction of the benchmark. It is **not** a CIS assessment tool. Large
areas — CloudTrail, AWS Config, CloudWatch alarms, KMS rotation, root-user controls, access-key
rotation, IMDSv2, VPC flow logs — are not implemented at all. The `cis` profile runs the mapped
rules only; passing it says nothing about the requirements Sentinel never checks.

"""End-to-end profile tests: scanner output through the real reporting pipeline.

Testing checks in isolation missed a whole class of bug. Splitting a rule into a
risk half and a compliance half, and unmapping the risk half, individually made
sense -- but composed, they made the worst possible S3 bucket invisible under
`profile: cis`. Only a test that runs the scanner and then applies the profile
can catch that, so these tests assert on what a user would actually receive.
"""
from __future__ import annotations

import boto3
from moto import mock_aws

from sentinel.cli import filter_ignored, run_scanners_with_coverage
from sentinel.core.config import Config
from sentinel.core.rule import apply_rule_config
from sentinel.core.suppression import apply_suppressions
from sentinel.modules.cloudscan.scanner import CloudScanner

_BPA_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _pipeline(config):
    """Exactly what `sentinel scan-all` produces, minus report serialisation."""
    findings, coverage = run_scanners_with_coverage({"cloudscan": CloudScanner}, config)
    findings = apply_rule_config(findings, config)
    findings = filter_ignored(findings, config.ignore_ids)
    findings = apply_suppressions(findings, config.suppressions)
    return findings, coverage


@mock_aws
def test_fully_unprotected_bucket_is_visible_under_cis_profile(aws_credentials):
    """The worst case must not fall between the risk rule and the compliance rule."""
    boto3.Session(region_name="us-east-1").client("s3").create_bucket(
        Bucket="fully-unprotected"
    )
    config = Config(aws_regions=["us-east-1"], profile="cis")

    findings, _ = _pipeline(config)

    bpa = [f for f in findings if f.resource == "fully-unprotected"]
    assert bpa, "a bucket with no Block Public Access at all produced no CIS finding"
    assert {f.id for f in bpa} == {"CLOUD-S3-BPA-NOT-STRICT"}
    assert all(f.compliance for f in bpa)


@mock_aws
def test_fully_unprotected_bucket_is_also_visible_under_baseline(aws_credentials):
    boto3.Session(region_name="us-east-1").client("s3").create_bucket(
        Bucket="fully-unprotected"
    )
    config = Config(aws_regions=["us-east-1"], profile="baseline")

    findings, _ = _pipeline(config)

    ids = {f.id for f in findings if f.resource == "fully-unprotected"}
    assert "CLOUD-S3-NO-BPA" in ids


@mock_aws
def test_bucket_protected_at_both_levels_is_clean_under_cis(aws_credentials):
    """The guard must not fire on a bucket that genuinely satisfies 2.1.4."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="properly-locked")
    s3.put_public_access_block(
        Bucket="properly-locked", PublicAccessBlockConfiguration=_BPA_ON
    )
    session.client("s3control").put_public_access_block(
        AccountId="123456789012", PublicAccessBlockConfiguration=_BPA_ON
    )
    config = Config(aws_regions=["us-east-1"], profile="cis")

    findings, _ = _pipeline(config)

    assert not [
        f for f in findings if f.resource == "properly-locked" and "BPA" in f.id
    ]


@mock_aws
def test_cis_profile_emits_only_mapped_rules(aws_credentials):
    """Anything surfacing in a CIS run must carry a control id."""
    session = boto3.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket="fully-unprotected")
    session.client("iam").create_user(UserName="nomfa")
    config = Config(aws_regions=["us-east-1"], profile="cis")

    findings, _ = _pipeline(config)

    unmapped = [
        f for f in findings
        if not f.compliance and not f.id.endswith(("-ERROR", "-SKIPPED"))
    ]
    assert unmapped == [], f"unmapped rules leaked into a CIS run: {unmapped}"

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sentinel.core.finding import Finding, Severity


def _valid_kwargs():
    return dict(
        id="CLOUD-S3-PUBLIC-001",
        module="cloudscan",
        severity=Severity.HIGH,
        title="Public S3 bucket",
        description="Bucket allows public read.",
        remediation="Set the bucket ACL to private.",
    )


def test_finding_created_with_valid_fields():
    f = Finding(**_valid_kwargs())
    assert f.id == "CLOUD-S3-PUBLIC-001"
    assert f.severity is Severity.HIGH
    assert f.evidence == {}          # default
    assert f.resource is None         # default


def test_timestamp_defaults_to_utc_now():
    f = Finding(**_valid_kwargs())
    assert f.timestamp.tzinfo is timezone.utc
    assert isinstance(f.timestamp, datetime)


def test_missing_required_field_raises():
    kwargs = _valid_kwargs()
    del kwargs["remediation"]
    with pytest.raises(ValidationError):
        Finding(**kwargs)


def test_invalid_severity_raises():
    kwargs = _valid_kwargs()
    kwargs["severity"] = "Catastrophic"
    with pytest.raises(ValidationError):
        Finding(**kwargs)


def test_severity_accepts_string_value():
    kwargs = _valid_kwargs()
    kwargs["severity"] = "Critical"
    f = Finding(**kwargs)
    assert f.severity is Severity.CRITICAL


def test_model_dump_json_is_serializable():
    f = Finding(**_valid_kwargs())
    data = f.model_dump(mode="json")
    assert data["severity"] == "High"
    assert isinstance(data["timestamp"], str)


def test_new_fields_default():
    from sentinel.core.finding import Confidence, Status
    f = Finding(**_valid_kwargs())
    assert f.confidence is Confidence.MEDIUM
    assert f.status is Status.OPEN
    assert f.asset is None


def test_dedupe_key_is_stable_and_serialized():
    f = Finding(**_valid_kwargs())
    key = f.dedupe_key
    assert len(key) == 64  # sha256 hex digest
    assert f.dedupe_key == key  # stable
    data = f.model_dump(mode="json")
    assert data["dedupe_key"] == key  # computed field is serialized


def test_dedupe_key_includes_account():
    from sentinel.core.asset import Asset

    def _in_account(account_id):
        kwargs = _valid_kwargs()
        kwargs["resource"] = "same-name"
        kwargs["asset"] = Asset(
            provider="aws", type="iam_user", id="same-name", account_id=account_id
        )
        return Finding(**kwargs)

    # the same resource id in two accounts must not collide
    assert _in_account("111111111111").dedupe_key != _in_account("222222222222").dedupe_key


def test_asset_can_be_attached():
    from sentinel.core.asset import Asset
    kwargs = _valid_kwargs()
    kwargs["asset"] = Asset(
        provider="aws", type="s3_bucket", id="b",
        account_id="123456789012", region="us-east-1",
    )
    f = Finding(**kwargs)
    assert f.asset.provider == "aws"
    assert f.asset.region == "us-east-1"


def test_category_and_references_default_and_set():
    f = Finding(**_valid_kwargs())
    assert f.category is None
    assert f.references == []

    kwargs = _valid_kwargs()
    kwargs["category"] = "Data Exposure"
    kwargs["references"] = ["https://example.test/doc"]
    f2 = Finding(**kwargs)
    assert f2.category == "Data Exposure"
    assert f2.references == ["https://example.test/doc"]

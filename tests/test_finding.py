import pytest
from datetime import datetime, timezone
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

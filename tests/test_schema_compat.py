"""Reading reports written by an older schema.

v0.2.0 replaced the coverage model and, in doing so, made its own diff raise a
ValidationError on every v0.1 report -- while the changelog claimed those reports
were still readable. The fixture in tests/fixtures is a real v0.1 document and
stays in the repo so the compatibility claim is checked rather than asserted.
"""
from __future__ import annotations

import json
import pathlib

from sentinel.core.diff import diff_reports, is_legacy_coverage

_FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def _v1() -> dict:
    return json.loads((_FIXTURES / "report_schema_v1.json").read_text(encoding="utf-8"))


def _v2(findings=None, units=None) -> dict:
    return {
        "schema_version": "2.0",
        "ruleset_digest": "4f53cda18c2baa0c",
        "config_digest": "9c1185a5c5e9fc54",
        "coverage": {
            "units": units if units is not None else [
                {"scanner": "cloudscan", "account_id": "123456789012",
                 "region": "ap-southeast-2", "check": "rds_encryption", "status": "ok"}
            ],
            "rules": ["CLOUD-RDS-UNENCRYPTED"],
        },
        "findings": findings or [],
    }


def test_v1_report_is_detected_as_legacy():
    assert is_legacy_coverage(_v1())
    assert not is_legacy_coverage(_v2())


def test_v1_report_can_be_diffed_without_raising():
    result = diff_reports(_v1(), _v2())

    assert isinstance(result["unassessed"], list)


def test_v1_report_never_confirms_a_resolution():
    """Across the schema change, dedupe_key comparability is not guaranteed:
    v0.2.0 renamed rules, and the key is derived partly from the rule title. A
    finding that is 'gone' may simply have been renamed."""
    result = diff_reports(_v1(), _v2())

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1
    assert result["unassessed"][0]["resource"] == "legacy-db"


def test_v1_comparison_explains_itself():
    warnings = " ".join(diff_reports(_v1(), _v2())["warnings"])

    assert "schema 1.x" in warnings
    assert "confirm a fix" in warnings


def test_a_malformed_coverage_block_is_untrusted_not_fatal():
    broken = _v2()
    broken["coverage"] = {"units": "not-a-list"}

    result = diff_reports(_v2(findings=[
        {"dedupe_key": "k", "id": "R1", "module": "cloudscan", "severity": "High"}
    ]), broken)

    assert result["resolved"] == []
    assert len(result["unassessed"]) == 1

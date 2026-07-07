import json
from sentinel.core.report import summarize, write_json, write_html, write_sarif


def test_summarize_counts_all_severities(sample_findings):
    summary = summarize(sample_findings)
    assert summary == {
        "Critical": 1, "High": 1, "Medium": 0, "Low": 1, "Info": 0
    }


def test_summarize_empty():
    assert summarize([]) == {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    }


def test_write_json_creates_file_with_expected_shape(sample_findings, tmp_path):
    path = write_json(sample_findings, tmp_path)
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["summary"]["Critical"] == 1
    assert len(payload["findings"]) == 3
    assert payload["findings"][0]["id"] == "CLOUD-S3-PUBLIC-001"
    assert "generated_at" in payload


def test_write_html_contains_summary_and_titles(sample_findings, tmp_path):
    path = write_html(sample_findings, tmp_path)
    assert path.exists()
    html = path.read_text(encoding="utf-8")
    assert "Public S3 bucket" in html
    assert "Brute-force login detected" in html
    assert "Critical" in html
    assert "Set the bucket ACL to private." in html


def test_write_html_shows_category_and_references(tmp_path):
    from sentinel.core.finding import Finding, Severity

    f = Finding(
        id="X", module="m", severity=Severity.HIGH, title="t",
        description="d", remediation="r",
        category="Data Exposure", references=["https://example.test/ref"],
    )
    html = write_html([f], tmp_path).read_text(encoding="utf-8")
    assert "Data Exposure" in html
    assert "https://example.test/ref" in html


def test_write_json_empty_findings(tmp_path):
    path = write_json([], tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["summary"]["High"] == 0


def test_write_sarif_is_valid_shape(sample_findings, tmp_path):
    path = write_sarif(sample_findings, tmp_path)
    doc = json.loads(path.read_text(encoding="utf-8"))

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Sentinel"

    # rules are de-duplicated by id
    rule_ids = [r["id"] for r in driver["rules"]]
    assert "CLOUD-S3-PUBLIC-001" in rule_ids
    assert len(rule_ids) == len(set(rule_ids))

    # one result per finding, with a valid ruleIndex
    assert len(run["results"]) == len(sample_findings)
    for result in run["results"]:
        assert 0 <= result["ruleIndex"] < len(driver["rules"])
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]

    # severity maps to SARIF level (Critical -> error, Low -> note)
    by_id = {r["ruleId"]: r for r in run["results"]}
    assert by_id["LOG-BRUTE-001"]["level"] == "error"      # Critical
    assert by_id["WEB-HEADER-001"]["level"] == "note"      # Low


def test_write_sarif_empty(tmp_path):
    path = write_sarif([], tmp_path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_write_sarif_has_stable_fingerprints(sample_findings, tmp_path):
    run1 = json.loads(write_sarif(sample_findings, tmp_path).read_text(encoding="utf-8"))
    run2 = json.loads(write_sarif(sample_findings, tmp_path).read_text(encoding="utf-8"))

    fps1 = [r["partialFingerprints"]["sentinelFingerprint/v1"] for r in run1["runs"][0]["results"]]
    fps2 = [r["partialFingerprints"]["sentinelFingerprint/v1"] for r in run2["runs"][0]["results"]]

    assert all(fps1)                 # every result carries a fingerprint
    assert fps1 == fps2              # stable across runs of the same findings
    assert len(set(fps1)) == len(fps1)  # distinct findings → distinct fingerprints

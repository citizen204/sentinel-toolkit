import json
from sentinel.core.report import summarize, write_json, write_html


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


def test_write_json_empty_findings(tmp_path):
    path = write_json([], tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["summary"]["High"] == 0

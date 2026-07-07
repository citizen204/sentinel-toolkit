import json
from pathlib import Path

import boto3
from moto import mock_aws
from typer.testing import CliRunner

from sentinel.cli import app

runner = CliRunner()


def test_unknown_scanner_exits_nonzero():
    result = runner.invoke(app, ["scan", "does-not-exist"])
    assert result.exit_code == 1
    assert "Unknown scanner" in result.stdout


@mock_aws
def test_scan_cloudscan_writes_report(aws_credentials, tmp_path):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    result = runner.invoke(
        app,
        ["scan", "cloudscan", "--output-dir", str(tmp_path), "--format", "json"],
    )
    assert result.exit_code == 0, result.stdout
    json_files = list(Path(tmp_path).glob("report-*.json"))
    assert len(json_files) == 1
    payload = json.loads(json_files[0].read_text(encoding="utf-8"))
    ids = {f["id"] for f in payload["findings"]}
    assert "CLOUD-S3-PUBLIC" in ids

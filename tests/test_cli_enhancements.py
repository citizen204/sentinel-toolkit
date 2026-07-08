import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws
from typer.testing import CliRunner

from sentinel.cli import _select_scanners, app
from sentinel.core.config import load_config

runner = CliRunner()


# --- --format enum -----------------------------------------------------------

def test_invalid_format_is_rejected():
    result = runner.invoke(app, ["scan-all", "--format", "xml"])
    assert result.exit_code != 0  # Typer rejects the bad enum value


@mock_aws
def test_sarif_format_writes_sarif_file(aws_credentials, tmp_path):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    result = runner.invoke(
        app, ["scan", "cloudscan", "--output-dir", str(tmp_path), "--format", "sarif"]
    )
    assert result.exit_code == 0, result.stdout
    sarif = list(Path(tmp_path).glob("report-*.sarif"))
    assert len(sarif) == 1
    doc = json.loads(sarif[0].read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


# --- --include / --exclude ---------------------------------------------------

def test_select_scanners_include_only():
    selected = _select_scanners("cloudscan", None)
    assert set(selected) == {"cloudscan"}


def test_select_scanners_exclude():
    selected = _select_scanners(None, "cloudscan")
    assert "cloudscan" not in selected
    assert "webscan" in selected


def test_select_scanners_unknown_raises():
    with pytest.raises(ValueError):
        _select_scanners("webscna", None)  # typo


def test_rules_command_lists_catalog():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "CLOUD-S3-PUBLIC" in result.stdout
    assert "NET-PORT-SCAN" in result.stdout


def test_unknown_include_exits_nonzero():
    result = runner.invoke(app, ["scan-all", "--include", "webscna"])
    assert result.exit_code == 1
    assert "Unknown scanner" in result.stdout


def test_unknown_exclude_exits_nonzero():
    result = runner.invoke(app, ["scan-all", "--exclude", "cloudscna"])
    assert result.exit_code == 1


def test_output_dir_falls_back_to_config(tmp_path):
    out = tmp_path / "myreports"
    cfg_file = tmp_path / "sentinel.yaml"
    cfg_file.write_text(f'output_dir: "{out.as_posix()}"\n', encoding="utf-8")

    # no --output-dir given → should use config's output_dir
    result = runner.invoke(
        app,
        ["scan-all", "--exclude", "cloudscan", "--config", str(cfg_file), "--format", "json"],
    )
    assert result.exit_code == 0, result.stdout
    assert len(list(out.glob("report-*.json"))) == 1


# --- init-config -------------------------------------------------------------

def test_init_config_writes_loadable_file(tmp_path):
    target = tmp_path / "sentinel.yaml"
    result = runner.invoke(app, ["init-config", "--path", str(target)])
    assert result.exit_code == 0
    assert target.exists()

    # the generated file must be a valid, loadable config
    cfg = load_config(target)
    assert cfg.output_dir == "reports"
    assert cfg.aws_profile == "my-audit-profile"


def test_init_config_refuses_overwrite_without_force(tmp_path):
    target = tmp_path / "sentinel.yaml"
    target.write_text("existing", encoding="utf-8")
    result = runner.invoke(app, ["init-config", "--path", str(target)])
    assert result.exit_code == 1
    assert target.read_text(encoding="utf-8") == "existing"

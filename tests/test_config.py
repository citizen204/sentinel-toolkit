from sentinel.core.config import load_config


def test_defaults_when_no_path():
    cfg = load_config(None)
    assert cfg.aws_profile is None
    assert cfg.target_url is None
    assert cfg.log_paths == []
    assert cfg.ignore_ids == []
    assert cfg.output_dir == "reports"


def test_load_from_yaml(tmp_path):
    cfg_file = tmp_path / "sentinel.yaml"
    cfg_file.write_text(
        "aws_profile: myacct\n"
        "target_url: https://example.test\n"
        "log_paths:\n"
        "  - /var/log/auth.log\n"
        "ignore_ids:\n"
        "  - CLOUD-S3-PUBLIC-001\n"
        "output_dir: out\n"
    )
    cfg = load_config(cfg_file)
    assert cfg.aws_profile == "myacct"
    assert cfg.target_url == "https://example.test"
    assert cfg.log_paths == ["/var/log/auth.log"]
    assert cfg.ignore_ids == ["CLOUD-S3-PUBLIC-001"]
    assert cfg.output_dir == "out"


def test_load_suppressions(tmp_path):
    cfg_file = tmp_path / "s.yaml"
    cfg_file.write_text(
        "suppressions:\n"
        "  - rule: CLOUD-IAM-NO-MFA\n"
        "    resource: bot\n"
        "    reason: accepted\n"
        "    expires: 2027-01-01\n",
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert len(cfg.suppressions) == 1
    assert cfg.suppressions[0].rule == "CLOUD-IAM-NO-MFA"
    assert cfg.suppressions[0].resource == "bot"
    assert str(cfg.suppressions[0].expires) == "2027-01-01"


def test_empty_yaml_file_yields_defaults(tmp_path):
    cfg_file = tmp_path / "empty.yaml"
    cfg_file.write_text("")
    cfg = load_config(cfg_file)
    assert cfg.output_dir == "reports"

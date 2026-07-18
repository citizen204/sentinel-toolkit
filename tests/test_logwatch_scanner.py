import pytest

from sentinel.core.config import Config
from sentinel.core.scanner import ScannerSkipped, all_scanners


def test_logwatch_registered():
    import sentinel.modules  # noqa: F401
    assert "logwatch" in all_scanners()


def test_run_reads_log_file(tmp_path):
    from sentinel.modules.logwatch.scanner import LogwatchScanner

    log = tmp_path / "auth.log"
    lines = [
        "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
        for _ in range(6)
    ]
    lines.append("Accepted password for root from 203.0.113.7 port 22 ssh2")
    log.write_text("\n".join(lines), encoding="utf-8")

    cfg = Config(log_paths=[str(log)])
    findings = LogwatchScanner().run(cfg)

    ids = {f.id for f in findings}
    assert ids == {"LOG-BRUTEFORCE", "LOG-ROOT-LOGIN"}


def test_bruteforce_threshold_comes_from_config(tmp_path):
    from sentinel.core.config import RuleConfig
    from sentinel.modules.logwatch.scanner import LogwatchScanner

    log = tmp_path / "auth.log"
    line = "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
    log.write_text("\n".join([line] * 6), encoding="utf-8")

    # 6 attempts trips the default threshold of 5 ...
    default_cfg = Config(log_paths=[str(log)])
    assert any(f.id == "LOG-BRUTEFORCE" for f in LogwatchScanner().run(default_cfg))

    # ... but not a configured threshold of 10
    tuned = Config(
        log_paths=[str(log)], rules={"LOG-BRUTEFORCE": RuleConfig(threshold=10)}
    )
    assert not any(f.id == "LOG-BRUTEFORCE" for f in LogwatchScanner().run(tuned))


def test_run_without_paths_is_skipped_not_clean():
    """Returning [] here is indistinguishable from "analyzed the logs, all fine"."""
    from sentinel.modules.logwatch.scanner import LogwatchScanner

    with pytest.raises(ScannerSkipped):
        LogwatchScanner().run(Config())


def test_run_with_every_path_missing_is_skipped(tmp_path):
    from sentinel.modules.logwatch.scanner import LogwatchScanner

    config = Config(log_paths=[str(tmp_path / "typo.log")])
    with pytest.raises(ScannerSkipped):
        LogwatchScanner().run(config)


def test_partially_missing_paths_are_reported_alongside_findings(tmp_path):
    """Partial coverage still produces findings, so the gap must travel with them."""
    from sentinel.modules.logwatch.scanner import LogwatchScanner

    good = tmp_path / "auth.log"
    line = "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
    good.write_text("\n".join([line] * 6), encoding="utf-8")
    config = Config(log_paths=[str(good), str(tmp_path / "absent.log")])

    findings = LogwatchScanner().run(config)

    assert any(f.id == "LOG-BRUTEFORCE" for f in findings)
    missing = [f for f in findings if f.id == "LOG-SOURCE-ERROR"]
    assert len(missing) == 1
    assert "absent.log" in missing[0].description

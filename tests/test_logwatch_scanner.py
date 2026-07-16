from sentinel.core.config import Config
from sentinel.core.scanner import all_scanners


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


def test_run_no_paths_returns_empty():
    from sentinel.modules.logwatch.scanner import LogwatchScanner
    assert LogwatchScanner().run(Config()) == []

import responses

from sentinel.core.config import Config
from sentinel.core.scanner import all_scanners

URL = "https://example.test/"


def test_webscan_registered():
    import sentinel.modules  # noqa: F401
    assert "webscan" in all_scanners()


@responses.activate
def test_run_uses_target_url():
    from sentinel.modules.webscan.scanner import WebScanner
    responses.add(responses.GET, URL, status=200, headers={})
    findings = WebScanner().run(Config(target_url=URL))
    assert len(findings) == 4
    assert all(f.id == "WEB-MISSING-HEADER" for f in findings)


def test_run_no_target_returns_empty():
    from sentinel.modules.webscan.scanner import WebScanner
    assert WebScanner().run(Config()) == []

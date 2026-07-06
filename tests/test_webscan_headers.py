import responses
from sentinel.modules.webscan.checks.headers import check_security_headers

URL = "https://example.test/"

_ALL_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


@responses.activate
def test_all_headers_missing_are_flagged():
    responses.add(responses.GET, URL, status=200, headers={})
    findings = check_security_headers(URL)
    flagged = {f.evidence["header"] for f in findings}
    assert flagged == set(_ALL_HEADERS)
    assert all(f.id == "WEB-MISSING-HEADER" for f in findings)
    assert all(f.resource == URL for f in findings)


@responses.activate
def test_present_headers_not_flagged():
    responses.add(responses.GET, URL, status=200, headers=_ALL_HEADERS)
    assert check_security_headers(URL) == []


@responses.activate
def test_partial_headers_flag_only_missing():
    responses.add(
        responses.GET, URL, status=200,
        headers={"Content-Security-Policy": "default-src 'self'"},
    )
    findings = check_security_headers(URL)
    flagged = {f.evidence["header"] for f in findings}
    assert "Content-Security-Policy" not in flagged
    assert "X-Frame-Options" in flagged

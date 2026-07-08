from sentinel.core.finding import Confidence, Severity
from sentinel.core.rule import Rule, register_rule

MISSING_HEADER = register_rule(Rule(
    id="WEB-MISSING-HEADER", module="webscan", severity=Severity.LOW,
    category="Web Hardening", confidence=Confidence.HIGH,
    title="Missing security header",
    description="An HTTP security response header is not set.",
    references=["https://owasp.org/www-project-secure-headers/"],
))

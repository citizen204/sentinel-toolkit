from sentinel.core.finding import Confidence, Severity
from sentinel.core.rule import Rule, register_rule

BRUTEFORCE = register_rule(Rule(
    id="LOG-BRUTEFORCE", module="logwatch", severity=Severity.HIGH,
    category="Authentication", confidence=Confidence.MEDIUM,
    title="Possible SSH brute-force attempt",
    description="Many failed SSH logins from a single source IP.",
    references=["https://attack.mitre.org/techniques/T1110/"],
))

ROOT_LOGIN = register_rule(Rule(
    id="LOG-ROOT-LOGIN", module="logwatch", severity=Severity.MEDIUM,
    category="Access Control", confidence=Confidence.MEDIUM,
    title="Direct privileged login",
    description="A successful direct root/admin SSH login.",
    references=["https://attack.mitre.org/techniques/T1078/"],
))

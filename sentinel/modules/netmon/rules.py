from sentinel.core.finding import Confidence, Severity
from sentinel.core.rule import Rule, register_rule

PORT_SCAN = register_rule(Rule(
    id="NET-PORT-SCAN", module="netmon", severity=Severity.HIGH,
    category="Reconnaissance", confidence=Confidence.MEDIUM,
    title="Possible port scan",
    description="A source IP connected to many distinct destination ports.",
    references=["https://attack.mitre.org/techniques/T1046/"],
))

HOST_SWEEP = register_rule(Rule(
    id="NET-HOST-SWEEP", module="netmon", severity=Severity.MEDIUM,
    category="Reconnaissance", confidence=Confidence.MEDIUM,
    title="Possible host sweep",
    description="A source IP contacted many distinct destination hosts.",
    references=["https://attack.mitre.org/techniques/T1018/"],
))

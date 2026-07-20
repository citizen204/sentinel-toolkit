"""The documented IAM policy is a contract, and these tests enforce it.

It drifted once already: the IAM.1 check began calling ListEntitiesForPolicy to
exclude permissions boundaries, and docs/aws-iam-policy.json was never updated.
Anyone following the README got AccessDenied on a real AWS account, and nothing in
CI knew, because no test connected the policy to the calls the code makes.
"""
from __future__ import annotations

import json
import pathlib
import re

from sentinel.modules.cloudscan.permissions import REQUIRED_ACTIONS, required_actions

_POLICY = pathlib.Path(__file__).resolve().parent.parent / "docs" / "aws-iam-policy.json"

# The only keys AWS accepts. A stray key (a "Comment", say) makes the whole
# document fail to apply with MalformedPolicyDocument.
_VALID_TOP_LEVEL = {"Version", "Id", "Statement"}
_VALID_STATEMENT = {
    "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction",
    "Resource", "NotResource", "Condition",
}


def _policy() -> dict:
    return json.loads(_POLICY.read_text(encoding="utf-8"))


def _granted_actions(policy: dict) -> set[str]:
    granted: set[str] = set()
    for statement in policy["Statement"]:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        granted.update([actions] if isinstance(actions, str) else actions)
    return granted


def test_policy_document_uses_only_valid_keys():
    """An unknown key is rejected by AWS outright, so the policy would never apply."""
    policy = _policy()

    assert not set(policy) - _VALID_TOP_LEVEL
    for statement in policy["Statement"]:
        unknown = set(statement) - _VALID_STATEMENT
        assert not unknown, f"{statement.get('Sid')} has invalid keys: {unknown}"


def test_policy_grants_every_action_the_code_calls():
    """The failure this guards against is silent until it hits a real account."""
    missing = sorted(required_actions() - _granted_actions(_policy()))

    assert not missing, (
        f"docs/aws-iam-policy.json is missing {missing}. Add them there, or remove "
        f"the call from the check and update REQUIRED_ACTIONS."
    )


def test_policy_grants_nothing_the_code_does_not_call():
    """Least privilege runs both ways: an unused grant is scope nobody asked for."""
    extra = sorted(_granted_actions(_policy()) - required_actions())

    assert not extra, (
        f"docs/aws-iam-policy.json grants {extra}, which no check calls. Remove them, "
        f"or record the caller in REQUIRED_ACTIONS."
    )


def test_every_check_name_is_a_real_check():
    """Keys must match the check names recorded in coverage units, or the mapping
    cannot be used to explain a CLOUD-CHECK-ERROR."""
    source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "sentinel" / "modules" / "cloudscan" / "scanner.py"
    ).read_text(encoding="utf-8")
    recorded = set(re.findall(r'record\(\s*"([a-z0-9_]+)"', source))
    # Names used outside record(): the two scope-setup steps and the assume loop.
    recorded |= {"region_discovery", "scan_context", "assume_role"}

    unknown = sorted(set(REQUIRED_ACTIONS) - recorded)
    assert not unknown, f"REQUIRED_ACTIONS names no such check: {unknown}"

    unmapped = sorted(recorded - set(REQUIRED_ACTIONS))
    assert not unmapped, f"checks with no documented permissions: {unmapped}"

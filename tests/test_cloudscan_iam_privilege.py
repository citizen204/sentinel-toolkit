import boto3
from moto import mock_aws

from sentinel.modules.cloudscan.checks.iam_privilege import (
    _managed_policy_is_admin,
    admin_paths,
    check_customer_managed_admin,
    check_effective_admin,
    is_admin_document,
)

_ADMIN_DOC = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
)
_READONLY_DOC = (
    '{"Version":"2012-10-17","Statement":'
    '[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}'
)


# --- wildcard detection ------------------------------------------------------

def test_is_admin_document_detects_wildcards():
    assert is_admin_document({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert is_admin_document(
        {"Statement": [{"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}]}
    )


def test_is_admin_document_ignores_scoped_and_deny():
    assert not is_admin_document(
        {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    )
    assert not is_admin_document(
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]}
    )
    assert not is_admin_document(
        {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    )


# --- the paths that actually reach a user ------------------------------------

@mock_aws
def test_admin_via_customer_managed_policy_on_user(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    arn = iam.create_policy(PolicyName="HomeGrownAdmin", PolicyDocument=_ADMIN_DOC)[
        "Policy"
    ]["Arn"]
    iam.create_user(UserName="wildcard-user")
    iam.attach_user_policy(UserName="wildcard-user", PolicyArn=arn)

    findings = check_effective_admin(session)

    assert [f.resource for f in findings] == ["wildcard-user"]
    assert "HomeGrownAdmin" in findings[0].evidence["admin_paths"][0]


@mock_aws
def test_admin_via_inline_user_policy(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="inline-user")
    iam.put_user_policy(
        UserName="inline-user", PolicyName="inline-admin", PolicyDocument=_ADMIN_DOC
    )

    findings = check_effective_admin(session)

    assert [f.resource for f in findings] == ["inline-user"]
    assert "inline policy" in findings[0].evidence["admin_paths"][0]


@mock_aws
def test_admin_inherited_through_group(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    arn = iam.create_policy(PolicyName="GroupAdmin", PolicyDocument=_ADMIN_DOC)["Policy"][
        "Arn"
    ]
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=arn)
    iam.create_user(UserName="group-member")
    iam.add_user_to_group(GroupName="admins", UserName="group-member")

    findings = check_effective_admin(session)

    # the whole point: nothing is attached to the user directly
    assert [f.resource for f in findings] == ["group-member"]
    assert "via group 'admins'" in findings[0].evidence["admin_paths"][0]


@mock_aws
def test_admin_via_inline_group_policy(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_group(GroupName="ops")
    iam.put_group_policy(
        GroupName="ops", PolicyName="ops-admin", PolicyDocument=_ADMIN_DOC
    )
    iam.create_user(UserName="ops-user")
    iam.add_user_to_group(GroupName="ops", UserName="ops-user")

    findings = check_effective_admin(session)

    assert [f.resource for f in findings] == ["ops-user"]


@mock_aws
def test_least_privilege_user_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    arn = iam.create_policy(PolicyName="ReadOnlyish", PolicyDocument=_READONLY_DOC)[
        "Policy"
    ]["Arn"]
    iam.create_user(UserName="scoped-user")
    iam.attach_user_policy(UserName="scoped-user", PolicyArn=arn)

    assert check_effective_admin(session) == []


@mock_aws
def test_customer_policy_named_administratoraccess_is_judged_on_content(aws_credentials):
    """A name is not a grant.

    Matching on PolicyName started life as a workaround for moto not preloading AWS
    managed policies, and it invented admin users out of naming conventions.
    """
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    arn = iam.create_policy(
        PolicyName="AdministratorAccess", PolicyDocument=_READONLY_DOC
    )["Policy"]["Arn"]
    iam.create_user(UserName="misleadingly-named")
    iam.attach_user_policy(UserName="misleadingly-named", PolicyArn=arn)

    assert check_effective_admin(session) == []


def test_only_the_aws_managed_admin_arn_short_circuits():
    """The AWS-managed ARN is trusted without a lookup; a same-named customer one is not."""
    class Unreadable:
        def get_policy(self, PolicyArn):
            raise AssertionError(f"should have read the document for {PolicyArn}")

    cache: dict[str, bool] = {}
    assert _managed_policy_is_admin(
        Unreadable(), "arn:aws:iam::aws:policy/AdministratorAccess", cache
    )
    # commercial, China, and GovCloud partitions all qualify
    assert _managed_policy_is_admin(
        Unreadable(), "arn:aws-cn:iam::aws:policy/AdministratorAccess", cache
    )
    assert _managed_policy_is_admin(
        Unreadable(), "arn:aws-us-gov:iam::aws:policy/AdministratorAccess", cache
    )


class _FakePaginator:
    def __init__(self, pages_for):
        self._pages_for = pages_for

    def paginate(self, **kwargs):
        return iter(self._pages_for(kwargs))


class _TruncatingIam:
    """An IAM stub that really splits results across pages.

    moto returns every item in a single response, so a moto-based test passes
    whether or not the code paginates. Only a stub can prove the paginator is used,
    and the bare list_* methods raise here to make first-page-only access fail loudly.
    """

    def get_paginator(self, operation):
        return _FakePaginator(lambda kwargs: self._pages(operation, kwargs))

    def _pages(self, operation, kwargs):
        if operation == "list_groups_for_user":
            # The admin grant is deliberately on the second page.
            return [
                {"Groups": [{"GroupName": "first-page-group"}]},
                {"Groups": [{"GroupName": "second-page-group"}]},
            ]
        if operation == "list_group_policies":
            if kwargs.get("GroupName") == "second-page-group":
                return [{"PolicyNames": []}, {"PolicyNames": ["late-admin"]}]
            return [{"PolicyNames": []}]
        return [{}]

    def __getattr__(self, name):
        if name.startswith("list_"):
            raise AssertionError(f"{name} must be called through a paginator")
        raise AttributeError(name)

    def get_group_policy(self, GroupName, PolicyName):
        return {"PolicyDocument": _ADMIN_DOC}


def test_admin_paths_reads_every_page():
    """IAM list calls truncate at 100; stopping at page one reads as 'no admin path'."""
    paths = admin_paths(_TruncatingIam(), "deep-user")

    assert paths == ["inline policy 'late-admin' via group 'second-page-group'"]


# --- the compliance question: customer managed policies, attached or not ------

@mock_aws
def test_unattached_customer_admin_policy_is_flagged(aws_credentials):
    """AWS IAM.1 fails the policy itself; attachment is irrelevant."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_policy(PolicyName="DormantAdmin", PolicyDocument=_ADMIN_DOC)

    findings = check_customer_managed_admin(session)

    assert [f.resource for f in findings] == ["DormantAdmin"]
    assert findings[0].id == "CLOUD-IAM-CUSTOM-POLICY-ADMIN"
    assert findings[0].evidence["attachment_count"] == 0


@mock_aws
def test_scoped_customer_policy_is_not_flagged(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_policy(PolicyName="Scoped", PolicyDocument=_READONLY_DOC)

    assert check_customer_managed_admin(session) == []

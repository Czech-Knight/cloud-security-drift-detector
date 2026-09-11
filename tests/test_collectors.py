import json
from datetime import UTC, datetime
from unittest.mock import Mock
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.stub import Stubber

from drift_detector.aws.cloudtrail import CloudTrailCollector
from drift_detector.aws.ec2 import SecurityGroupCollector, flatten_permissions
from drift_detector.aws.iam import IAMCollector
from drift_detector.aws.s3 import S3Collector
from drift_detector.aws.session import AWSCollector
from drift_detector.baseline.normalizers import normalize_state
from drift_detector.demo import run_demo
from drift_detector.models import DetectorError, MissingResource


def s3_responses(stub, resource, state, *, encryption_missing=False, malformed_status=False):
    args = {"Bucket": resource.id, "ExpectedBucketOwner": "123456789012"}
    stub.add_response(
        "get_bucket_acl",
        {
            "Owner": {"ID": "owner"},
            "Grants": [
                {"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}
            ],
        },
        args,
    )
    stub.add_response(
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": state["public_access_block"]},
        args,
    )
    stub.add_response("get_bucket_policy", {"Policy": json.dumps(state["policy"])}, args)
    stub.add_response(
        "get_bucket_policy_status",
        {} if malformed_status else {"PolicyStatus": {"IsPublic": False}},
        args,
    )
    if encryption_missing:
        stub.add_client_error(
            "get_bucket_encryption",
            "ServerSideEncryptionConfigurationNotFoundError",
            expected_params=args,
        )
    else:
        stub.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                            "BucketKeyEnabled": False,
                        }
                    ]
                }
            },
            args,
        )
    stub.add_response(
        "get_bucket_ownership_controls",
        {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
        args,
    )
    stub.add_response("get_bucket_versioning", {"Status": "Enabled"}, args)


def test_s3_real_sdk_shapes_and_owner_guard(aws_client, resources, states):
    client = aws_client("s3")
    with Stubber(client) as stub:
        s3_responses(stub, resources["s3"], states["s3"])
        actual = S3Collector(client, "123456789012").collect(resources["s3"])
        assert normalize_state("s3", actual) == resources["s3"].expected
        stub.assert_no_pending_responses()


def test_s3_missing_encryption_not_confused_with_denied(aws_client, resources, states):
    client = aws_client("s3")
    with Stubber(client) as stub:
        s3_responses(stub, resources["s3"], states["s3"], encryption_missing=True)
        actual = S3Collector(client, "123456789012").collect(resources["s3"])
        assert actual["encryption"] is None
        stub.assert_no_pending_responses()


def test_s3_denied_raises(aws_client, resources):
    client = aws_client("s3")
    with Stubber(client) as stub:
        stub.add_client_error("get_bucket_acl", "AccessDenied")
        with pytest.raises(ClientError):
            S3Collector(client, "123456789012").collect(resources["s3"])


def test_s3_malformed_policy_status_not_clean(aws_client, resources, states):
    client = aws_client("s3")
    with Stubber(client) as stub:
        s3_responses(stub, resources["s3"], states["s3"], malformed_status=True)
        with pytest.raises(KeyError):
            S3Collector(client, "123456789012").collect(resources["s3"])


def test_s3_absent_config_codes_only(aws_client, resources):
    client = aws_client("s3")
    args = {"Bucket": resources["s3"].id, "ExpectedBucketOwner": "123456789012"}
    with Stubber(client) as stub:
        stub.add_response("get_bucket_acl", {"Owner": {"ID": "o"}, "Grants": []}, args)
        for method, code in [
            ("get_public_access_block", "NoSuchPublicAccessBlockConfiguration"),
            ("get_bucket_policy", "NoSuchBucketPolicy"),
            ("get_bucket_policy_status", "NoSuchBucketPolicy"),
            ("get_bucket_encryption", "ServerSideEncryptionConfigurationNotFoundError"),
            ("get_bucket_ownership_controls", "OwnershipControlsNotFoundError"),
        ]:
            stub.add_client_error(method, code, expected_params=args)
        stub.add_response("get_bucket_versioning", {}, args)
        state = S3Collector(client, "123456789012").collect(resources["s3"])
        assert not any(state["public_access_block"].values())
        assert state["policy"] is None and state["versioning"] == "Disabled"
        stub.assert_no_pending_responses()


def test_security_group_sdk_flattens_all_sources(aws_client, resources):
    client = aws_client("ec2")
    permission = {
        "IpProtocol": "6",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        "UserIdGroupPairs": [{"GroupId": "sg-abcdef12", "UserId": "123456789012"}],
        "PrefixListIds": [{"PrefixListId": "pl-12345678"}],
    }
    with Stubber(client) as stub:
        stub.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": resources["security_group"].id,
                        "IpPermissions": [permission],
                        "IpPermissionsEgress": [],
                    }
                ]
            },
            {"GroupIds": [resources["security_group"].id]},
        )
        actual = SecurityGroupCollector(client).collect(resources["security_group"])
        assert len(actual["ingress"]) == 4
        assert {r["source_type"] for r in actual["ingress"]} == {
            "ipv4",
            "ipv6",
            "security_group",
            "prefix_list",
        }
        assert flatten_permissions([permission, permission])[:4] == actual["ingress"]


def test_deleted_group(aws_client, resources):
    client = aws_client("ec2")
    with Stubber(client) as stub:
        stub.add_client_error("describe_security_groups", "InvalidGroup.NotFound")
        with pytest.raises(MissingResource):
            SecurityGroupCollector(client).collect(resources["security_group"])


def role_response(resource):
    return {
        "Role": {
            "Path": "/",
            "RoleName": resource.id,
            "RoleId": "AROATEST1234567890123",
            "Arn": resource.arn,
            "CreateDate": datetime.now(UTC),
            "AssumeRolePolicyDocument": quote(json.dumps(resource.expected["trust_policy"])),
        }
    }


def test_iam_pagination_and_default_version(aws_client, resources):
    client = aws_client("iam")
    resource = resources["iam_role"]
    arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    admin = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    with Stubber(client) as stub:
        stub.add_response("get_role", role_response(resource), {"RoleName": resource.id})
        stub.add_response(
            "list_role_policies",
            {"PolicyNames": [], "IsTruncated": True, "Marker": "next"},
            {"RoleName": resource.id},
        )
        stub.add_response(
            "list_role_policies",
            {"PolicyNames": ["Extra"], "IsTruncated": False},
            {"RoleName": resource.id, "Marker": "next"},
        )
        stub.add_response(
            "get_role_policy",
            {"RoleName": resource.id, "PolicyName": "Extra", "PolicyDocument": json.dumps(admin)},
            {"RoleName": resource.id, "PolicyName": "Extra"},
        )
        stub.add_response(
            "list_attached_role_policies",
            {
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": arn}],
                "IsTruncated": False,
            },
            {"RoleName": resource.id},
        )
        stub.add_response("get_policy", {"Policy": {"DefaultVersionId": "v2"}}, {"PolicyArn": arn})
        stub.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "VersionId": "v2",
                    "Document": quote(json.dumps(admin)),
                    "IsDefaultVersion": True,
                }
            },
            {"PolicyArn": arn, "VersionId": "v2"},
        )
        actual = IAMCollector(client).collect(resource)
        assert actual["attached_policies"][arn]["Statement"][0]["Action"] == ["*"]
        assert actual["trust_policy"] == resource.expected["trust_policy"]
        stub.assert_no_pending_responses()


def test_role_deletion(aws_client, resources):
    client = aws_client("iam")
    with Stubber(client) as stub:
        stub.add_client_error("get_role", "NoSuchEntity")
        with pytest.raises(MissingResource):
            IAMCollector(client).collect(resources["iam_role"])


@pytest.mark.parametrize("kind", ["account", "region", "no_credentials"])
def test_identity_safety_before_resource_scan(baseline, monkeypatch, kind):
    session = Mock()
    session.region_name = "us-east-1" if kind == "region" else baseline.aws_region
    sts = session.client.return_value
    sts.get_caller_identity.return_value = {
        "Account": "999999999999" if kind == "account" else baseline.aws_account_id
    }
    if kind == "no_credentials":
        sts.get_caller_identity.side_effect = NoCredentialsError()
    monkeypatch.setattr("drift_detector.aws.session.boto3.Session", lambda **kwargs: session)
    with pytest.raises(DetectorError):
        AWSCollector(baseline)
    if kind == "region":
        session.client.assert_not_called()


def test_cloudtrail_is_optional_and_global_iam_region(aws_client, resources):
    client = aws_client("cloudtrail")
    calls = []

    class AWS:
        region = "ap-southeast-2"

        def client(self, service, region=None):
            calls.append(region)
            return client

    report = run_demo()
    with Stubber(client) as stub:
        stub.add_client_error("lookup_events", "AccessDeniedException")
        CloudTrailCollector(AWS()).enrich(report, [resources["iam_role"]])
    assert calls == ["us-east-1"]
    assert report.exit_code() == 1 and not report.errors
    assert any("unavailable" in w for w in report.warnings)


def test_cloudtrail_skips_reads_and_labels_correlation(aws_client, resources):
    client = aws_client("cloudtrail")
    now = datetime.now(UTC)
    events = [
        {
            "EventId": "event-write",
            "EventName": "AuthorizeSecurityGroupIngress",
            "EventTime": now,
            "CloudTrailEvent": json.dumps(
                {
                    "readOnly": False,
                    "userIdentity": {"arn": "arn:aws:iam::123456789012:role/example"},
                    "sourceIPAddress": "203.0.113.50",
                }
            ),
        },
        {
            "EventId": "event-read",
            "EventName": "DescribeSecurityGroups",
            "EventTime": now,
            "CloudTrailEvent": json.dumps({"readOnly": True}),
        },
    ]

    class AWS:
        region = "ap-southeast-2"

        def client(self, *args, **kwargs):
            return client

    report = run_demo()
    with Stubber(client) as stub:
        stub.add_response("lookup_events", {"Events": events})
        CloudTrailCollector(AWS()).enrich(report, [resources["security_group"]])
    finding = next(f for f in report.findings if f.rule_id == "SG_PUBLIC_SSH")
    assert len(finding.cloudtrail_events) == 1
    assert finding.cloudtrail_events[0]["label"] == "Possible related CloudTrail event"

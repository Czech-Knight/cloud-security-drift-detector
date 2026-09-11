from copy import deepcopy

import pytest

from drift_detector.baseline.normalizers import normalize_state, policy
from drift_detector.rules import iam_rules, s3_rules, security_group_rules


def ids(findings):
    return {f.rule_id for f in findings}


def evaluate(kind, resources, state):
    fn = {
        "s3": s3_rules.evaluate,
        "security_group": security_group_rules.evaluate,
        "iam_role": iam_rules.evaluate,
    }[kind]
    return fn(resources[kind], normalize_state(kind, state))


@pytest.mark.parametrize("kind", ["s3", "security_group", "iam_role"])
def test_unchanged_baselines_clean(kind, resources, states):
    assert evaluate(kind, resources, states[kind]) == []


@pytest.mark.parametrize(
    "port,expected",
    [
        (22, "SG_PUBLIC_SSH"),
        (3389, "SG_PUBLIC_RDP"),
        (5432, "SG_PUBLIC_DATABASE_PORT"),
        (3306, "SG_PUBLIC_DATABASE_PORT"),
        (1433, "SG_PUBLIC_DATABASE_PORT"),
        (6379, "SG_PUBLIC_DATABASE_PORT"),
        (27017, "SG_PUBLIC_DATABASE_PORT"),
    ],
)
@pytest.mark.parametrize("source,family", [("0.0.0.0/0", "ipv4"), ("::/0", "ipv6")])
def test_public_sensitive_ports(port, expected, source, family, resources, states):
    state = states["security_group"]
    state["ingress"].append(
        {
            "protocol": "tcp",
            "from_port": port,
            "to_port": port,
            "source_type": family,
            "source": source,
        }
    )
    findings = evaluate("security_group", resources, state)
    assert expected in ids(findings)
    assert next(f for f in findings if f.rule_id == expected).severity == "CRITICAL"
    if family == "ipv6":
        assert "SG_IPV6_PUBLIC_EXPOSURE" in ids(findings)


@pytest.mark.parametrize(
    "protocol,start,end", [("-1", None, None), ("tcp", 0, 65535), ("udp", 0, 65535)]
)
def test_all_ports(protocol, start, end, resources, states):
    state = states["security_group"]
    state["ingress"].append(
        {
            "protocol": protocol,
            "from_port": start,
            "to_port": end,
            "source_type": "ipv4",
            "source": "0.0.0.0/0",
        }
    )
    assert "SG_ALL_PORTS_PUBLIC" in ids(evaluate("security_group", resources, state))


def test_range_captures_multiple_dangerous_ports(resources, states):
    state = states["security_group"]
    state["ingress"].append(
        {
            "protocol": "6",
            "from_port": 20,
            "to_port": 6000,
            "source_type": "ipv4",
            "source": "0.0.0.0/0",
        }
    )
    assert {"SG_PUBLIC_SSH", "SG_PUBLIC_RDP", "SG_PUBLIC_DATABASE_PORT"} <= ids(
        evaluate("security_group", resources, state)
    )


def test_icmp_type_22_is_not_ssh(resources, states):
    state = states["security_group"]
    state["ingress"].append(
        {
            "protocol": "icmp",
            "from_port": 22,
            "to_port": -1,
            "source_type": "ipv4",
            "source": "0.0.0.0/0",
        }
    )
    assert "SG_PUBLIC_SSH" not in ids(evaluate("security_group", resources, state))


def test_trusted_cidr_broadened(resources, states):
    states["security_group"]["ingress"][
        1 if states["security_group"]["ingress"][0]["from_port"] == 443 else 0
    ]["source"] = "203.0.113.0/24"
    assert "SG_CIDR_BROADENED" in ids(
        evaluate("security_group", resources, states["security_group"])
    )


def test_unexpected_internal_ingress_and_egress(resources, states):
    state = states["security_group"]
    rule = {
        "protocol": "tcp",
        "from_port": 8080,
        "to_port": 8080,
        "source_type": "ipv4",
        "source": "10.0.0.0/8",
    }
    state["ingress"].append(rule)
    state["egress"].append(rule)
    assert {"SG_UNEXPECTED_INGRESS", "SG_UNEXPECTED_EGRESS"} <= ids(
        evaluate("security_group", resources, state)
    )


def test_duplicate_and_order_only_sg_not_drift(resources, states):
    state = states["security_group"]
    state["ingress"].reverse()
    state["ingress"].append(state["ingress"][0])
    assert evaluate("security_group", resources, state) == []


@pytest.mark.parametrize(
    "key", ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
)
def test_s3_pab(key, resources, states):
    states["s3"]["public_access_block"][key] = False
    assert "S3_PUBLIC_ACCESS_BLOCK_DISABLED" in ids(evaluate("s3", resources, states["s3"]))


def test_s3_missing_encryption_is_not_plaintext_claim(resources, states):
    states["s3"]["encryption"] = None
    f = next(
        f for f in evaluate("s3", resources, states["s3"]) if f.rule_id == "S3_ENCRYPTION_DISABLED"
    )
    assert "does not mean" in f.explanation and "SSE-S3" in f.explanation


def test_s3_kms_to_aes_detected(resources, states):
    resources["s3"].expected["encryption"]["algorithm"] = "aws:kms"
    resources["s3"].expected["encryption"]["kms_key_id"] = (
        "arn:aws:kms:ap-southeast-2:123456789012:key/example"
    )
    assert "S3_ENCRYPTION_WEAKENED" in ids(evaluate("s3", resources, states["s3"]))


def test_s3_public_status(resources, states):
    states["s3"]["policy_public"] = True
    assert "S3_PUBLIC_POLICY" in ids(evaluate("s3", resources, states["s3"]))


@pytest.mark.parametrize("group", ["AllUsers", "AuthenticatedUsers"])
def test_s3_public_acl(group, resources, states):
    states["s3"]["acl"].append(
        {"grantee": f"http://acs.amazonaws.com/groups/global/{group}", "permission": "READ"}
    )
    assert "S3_PUBLIC_ACL" in ids(evaluate("s3", resources, states["s3"]))


def test_s3_private_acl_and_ownership(resources, states):
    states["s3"]["acl"].append({"grantee": "other-account-id", "permission": "WRITE"})
    states["s3"]["ownership"] = "BucketOwnerPreferred"
    assert {"S3_ACL_CHANGED", "S3_OWNERSHIP_CHANGED"} <= ids(
        evaluate("s3", resources, states["s3"])
    )


def test_s3_versioning_and_https_removed(resources, states):
    states["s3"]["versioning"] = "Suspended"
    states["s3"]["policy"] = None
    assert {"S3_VERSIONING_DISABLED", "S3_HTTPS_ONLY_POLICY_REMOVED"} <= ids(
        evaluate("s3", resources, states["s3"])
    )


@pytest.mark.parametrize("mutation", ["action", "resource", "condition", "principal"])
def test_narrowed_https_deny_is_not_universal(mutation, resources, states):
    state = states["s3"]
    statement = state["policy"]["Statement"][0]
    if mutation == "action":
        statement["Action"] = ["s3:getobject"]
    elif mutation == "resource":
        statement["Resource"] = [resources["s3"].arn + "/*"]
    elif mutation == "condition":
        statement["Condition"]["StringEquals"] = {"aws:PrincipalAccount": ["123456789012"]}
    else:
        statement["Principal"] = {"AWS": ["arn:aws:iam::123456789012:root"]}
    assert "S3_HTTPS_ONLY_POLICY_REMOVED" in ids(evaluate("s3", resources, state))


def add_policy(state, actions, resource="*", effect="Allow"):
    state["inline_policies"]["Extra"] = {
        "Version": "2012-10-17",
        "Statement": {"Effect": effect, "Action": actions, "Resource": resource},
    }


def test_iam_admin_attached(resources, states):
    states["iam_role"]["attached_policies"]["arn:aws:iam::aws:policy/AdministratorAccess"] = {
        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
    }
    assert {
        "IAM_ADMIN_POLICY_ATTACHED",
        "IAM_WILDCARD_ACTION",
        "IAM_WILDCARD_RESOURCE",
        "IAM_PRIVILEGE_ESCALATION_RISK",
    } <= ids(evaluate("iam_role", resources, states["iam_role"]))


@pytest.mark.parametrize(
    "actions",
    [
        ["iam:PutRolePolicy"],
        ["iam:AttachRolePolicy"],
        ["iam:CreatePolicyVersion"],
        ["iam:SetDefaultPolicyVersion"],
        ["iam:UpdateAssumeRolePolicy"],
        ["iam:PassRole", "lambda:CreateFunction"],
        ["sts:AssumeRole"],
    ],
)
def test_escalation_heuristics(actions, resources, states):
    add_policy(states["iam_role"], actions)
    assert "IAM_PRIVILEGE_ESCALATION_RISK" in ids(
        evaluate("iam_role", resources, states["iam_role"])
    )


def test_deny_wildcards_not_privilege_grants(resources, states):
    add_policy(states["iam_role"], "*", effect="Deny")
    found = ids(evaluate("iam_role", resources, states["iam_role"]))
    assert "IAM_INLINE_POLICY_ADDED" in found
    assert (
        not {"IAM_WILDCARD_ACTION", "IAM_WILDCARD_RESOURCE", "IAM_PRIVILEGE_ESCALATION_RISK"}
        & found
    )


def test_inherently_unscopable_read_resource_not_flagged(resources, states):
    add_policy(states["iam_role"], ["ec2:DescribeSecurityGroups", "cloudtrail:LookupEvents"])
    assert "IAM_WILDCARD_RESOURCE" not in ids(evaluate("iam_role", resources, states["iam_role"]))


@pytest.mark.parametrize(
    "principal", ["*", {"AWS": "*"}, {"AWS": ["arn:aws:iam::999999999999:root"]}]
)
def test_trust_principal_broadening(principal, resources, states):
    states["iam_role"]["trust_policy"]["Statement"][0]["Principal"] = principal
    assert "IAM_TRUST_POLICY_BROADENED" in ids(evaluate("iam_role", resources, states["iam_role"]))


def test_policy_removed(resources, states):
    states["iam_role"]["inline_policies"] = {}
    assert "IAM_BASELINE_POLICY_REMOVED" in ids(evaluate("iam_role", resources, states["iam_role"]))


def test_managed_policy_version_change(resources, states):
    arn = "arn:aws:iam::123456789012:policy/Existing"
    original = policy(
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example/prefix/*",
            }
        }
    )
    resources["iam_role"].expected["attached_policies"][arn] = original
    states["iam_role"]["attached_policies"][arn] = {
        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
    }
    assert {"IAM_POLICY_CHANGED", "IAM_WILDCARD_ACTION"} <= ids(
        evaluate("iam_role", resources, states["iam_role"])
    )


def test_negated_allow(resources, states):
    states["iam_role"]["inline_policies"]["Extra"] = {
        "Statement": {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    }
    assert "IAM_NEGATED_ALLOW" in ids(evaluate("iam_role", resources, states["iam_role"]))


def test_policy_order_scalar_list_sid_and_encoding_equal():
    import json
    from urllib.parse import quote

    a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "a",
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject"],
                "Resource": ["b", "a"],
                "Principal": {"AWS": "x"},
            }
        ],
    }
    b = {
        "Statement": {
            "Effect": "Allow",
            "Principal": {"AWS": ["x"]},
            "Resource": ["a", "b"],
            "Action": ["s3:GetObject", "s3:ListBucket"],
        },
        "Version": "2012-10-17",
    }
    assert policy(a) == policy(quote(json.dumps(b)))
    copied = deepcopy(a)
    copied["Statement"].append({"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "a"})
    reversed_copy = deepcopy(copied)
    reversed_copy["Statement"].reverse()
    assert policy(copied) == policy(reversed_copy)


def test_scoped_object_prefix_is_not_account_wide_resource(resources, states):
    add_policy(states["iam_role"], ["s3:GetObject"], "arn:aws:s3:::example/reports/*")
    assert "IAM_WILDCARD_RESOURCE" not in ids(evaluate("iam_role", resources, states["iam_role"]))

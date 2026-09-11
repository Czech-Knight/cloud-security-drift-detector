"""Bucket settings, not an effective public-access or object-content evaluator."""

from drift_detector.models import Resource
from drift_detector.rules.catalog import finding

PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def https_enforced(policy: dict | None, bucket_arn: str) -> bool:
    covered = set()
    for statement in (policy or {}).get("Statement", []):
        principal = statement.get("Principal")
        is_all = principal == "*" or principal == {"AWS": ["*"]}
        condition = statement.get("Condition", {})
        # Extra conditions narrow the deny, so they cannot establish universal enforcement.
        bools = condition.get("Bool", {})
        transport = bools.get("aws:SecureTransport", [])
        secure_deny = (
            set(condition) == {"Bool"}
            and set(bools) == {"aws:SecureTransport"}
            and [str(x).lower() for x in transport] == ["false"]
        )
        if (
            statement.get("Effect") == "Deny"
            and is_all
            and secure_deny
            and ("s3:*" in statement.get("Action", []) or "*" in statement.get("Action", []))
        ):
            covered.update(statement.get("Resource", []))
    return "*" in covered or {bucket_arn, bucket_arn + "/*"}.issubset(covered)


def evaluate(resource: Resource, actual: dict) -> list:
    expected = resource.expected
    result = []

    def add(rule, key, severity=None):
        result.append(finding(rule, resource, expected[key], actual[key], severity))

    if any(
        value and not actual["public_access_block"][key]
        for key, value in expected["public_access_block"].items()
    ):
        add("S3_PUBLIC_ACCESS_BLOCK_DISABLED", "public_access_block")
    if actual["policy_public"] and not expected["policy_public"]:
        result.append(
            finding(
                "S3_PUBLIC_POLICY",
                resource,
                {"is_public": expected["policy_public"], "policy": expected["policy"]},
                {"is_public": actual["policy_public"], "policy": actual["policy"]},
            )
        )
    if expected["acl"] != actual["acl"]:
        newly_public = any(
            g.get("grantee") in PUBLIC_GROUPS and g not in expected["acl"] for g in actual["acl"]
        )
        add("S3_PUBLIC_ACL" if newly_public else "S3_ACL_CHANGED", "acl")
    if expected["ownership"] != actual["ownership"]:
        add(
            "S3_OWNERSHIP_CHANGED",
            "ownership",
            "HIGH" if actual["ownership"] != "BucketOwnerEnforced" else "LOW",
        )
    if expected["encryption"] != actual["encryption"]:
        old, new = expected["encryption"], actual["encryption"]
        if new is None:
            add("S3_ENCRYPTION_DISABLED", "encryption")
        elif old and any(old.get(k) != new.get(k) for k in ("algorithm", "kms_key_id")):
            add("S3_ENCRYPTION_WEAKENED", "encryption")
        else:
            add("S3_ENCRYPTION_CONFIGURATION_CHANGED", "encryption")
    if expected["versioning"] == "Enabled" and actual["versioning"] != "Enabled":
        add("S3_VERSIONING_DISABLED", "versioning")
    if expected["policy"] != actual["policy"]:
        add("S3_POLICY_CHANGED", "policy")
        if https_enforced(expected["policy"], resource.arn) and not https_enforced(
            actual["policy"], resource.arn
        ):
            add("S3_HTTPS_ONLY_POLICY_REMOVED", "policy")
    return result

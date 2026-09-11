#!/usr/bin/env python3
"""Regenerate the security reference from implemented rule metadata."""

from pathlib import Path

from drift_detector.rules.catalog import CATALOG

CONDITIONS = {
    "RESOURCE_MISSING": "AWS positively reports a monitored resource absent.",
    "S3_PUBLIC_ACCESS_BLOCK_DISABLED": "A baseline true public-access guard becomes false.",
    "S3_PUBLIC_POLICY": "AWS IsPublic changes from false to true.",
    "S3_PUBLIC_ACL": "An added ACL grant names AllUsers or AuthenticatedUsers.",
    "S3_ACL_CHANGED": "Other normalized bucket ACL grants change.",
    "S3_OWNERSHIP_CHANGED": "Ownership mode changes; restoration to BucketOwnerEnforced uses LOW.",
    "S3_ENCRYPTION_DISABLED": "A previously present default encryption configuration is absent.",
    "S3_ENCRYPTION_WEAKENED": "Algorithm or KMS key differs from an existing encryption baseline.",
    "S3_ENCRYPTION_CONFIGURATION_CHANGED": "Other encryption differences, e.g. Bucket Key setting.",
    "S3_VERSIONING_DISABLED": "Enabled versioning changes to Suspended or Disabled.",
    "S3_HTTPS_ONLY_POLICY_REMOVED": "Baseline universal insecure-transport deny no longer covers bucket and objects.",
    "S3_POLICY_CHANGED": "Normalized bucket policy changes, independently of AWS public status.",
    "SG_PUBLIC_SSH": "New public TCP range includes port 22.",
    "SG_PUBLIC_RDP": "New public TCP range includes port 3389.",
    "SG_PUBLIC_DATABASE_PORT": "New public TCP/UDP range includes 1433, 3306, 5432, 6379 or 27017.",
    "SG_ALL_PORTS_PUBLIC": "New public all-protocol rule or TCP/UDP range 0–65535.",
    "SG_IPV6_PUBLIC_EXPOSURE": "New ingress has source ::/0; may accompany a CRITICAL service rule.",
    "SG_UNEXPECTED_INGRESS": "Other added ingress; MEDIUM for internal sources, HIGH for public sources.",
    "SG_CIDR_BROADENED": "Same protocol/ports with a strict supernet of an approved source.",
    "SG_UNEXPECTED_EGRESS": "Added egress; MEDIUM internal, HIGH public.",
    "IAM_ADMIN_POLICY_ATTACHED": "New AWS AdministratorAccess managed-policy attachment.",
    "IAM_BROAD_MANAGED_POLICY": "New AWS-managed FullAccess/PowerUserAccess policy attachment.",
    "IAM_UNEXPECTED_POLICY_ATTACHMENT": "Other new managed policy ARN.",
    "IAM_BASELINE_POLICY_REMOVED": "An expected inline policy or managed attachment is absent.",
    "IAM_INLINE_POLICY_ADDED": "An inline policy name is newly present.",
    "IAM_POLICY_CHANGED": "Existing inline or attached default-version normalized document changes.",
    "IAM_WILDCARD_ACTION": "Added Allow statement uses wildcard action patterns.",
    "IAM_WILDCARD_RESOURCE": "Added Allow uses Resource:* exactly, excluding a small set of inherently global read actions. Scoped object-prefix ARNs are not treated as account-wide resources.",
    "IAM_NEGATED_ALLOW": "Added Allow statement contains NotAction or NotResource.",
    "IAM_PRIVILEGE_ESCALATION_RISK": "Added Allow includes selected IAM mutation, broad AssumeRole, or role passing plus workload creation in the inspected policy.",
    "IAM_TRUST_POLICY_BROADENED": "Changed trust includes wildcard principals or adds Allow principals.",
    "IAM_TRUST_POLICY_CHANGED": "Other normalized trust condition/action changes.",
}


def main():
    assert set(CONDITIONS) == set(CATALOG), "Add a documented condition for every implemented rule."
    lines = [
        "# Implemented security rules",
        "",
        "The table is generated from the same metadata used by the detector. Severity is the default; noted context-dependent overrides are implemented in the rule functions. Rules operate on differences from the approved baseline, not as a comprehensive account posture audit.",
        "",
        "| Rule ID | Resource | Severity | Condition | Risk | Recommended remediation |",
        "|---|---|---|---|---|---|",
    ]
    for rule, (severity, _title, risk, remedy) in CATALOG.items():
        family = "All monitored" if rule == "RESOURCE_MISSING" else rule.split("_")[0]
        lines.append(
            f"| `{rule}` | {family} | {severity} | {CONDITIONS[rule]} | {risk} | {remedy} |"
        )
    lines += [
        "",
        "All findings append reviewed Terraform plan/apply/rescan guidance. Removed ingress can appear only in the separate configuration-drift list. The IAM exception list and escalation set are intentionally scoped, not complete authorization analysis.",
        "",
        "To add a rule, update its resource family's evaluate function, CATALOG, this generator's condition mapping, and meaningful positive/negative tests. Run `python scripts/generate_rule_docs.py`.",
        "",
    ]
    Path("docs/security-rules.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()

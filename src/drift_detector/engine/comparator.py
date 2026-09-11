"""Configuration deltas and security findings remain separate concepts."""

from drift_detector.rules import iam_rules, s3_rules, security_group_rules

RULES = {
    "s3": s3_rules.evaluate,
    "security_group": security_group_rules.evaluate,
    "iam_role": iam_rules.evaluate,
}


def compare(resource, actual):
    changes = [
        {
            "resource_type": resource.type,
            "resource_id": resource.id,
            "property": key,
            "expected": resource.expected[key],
            "actual": actual[key],
        }
        for key in resource.expected
        if resource.expected[key] != actual[key]
    ]
    return changes, RULES[resource.type](resource, actual)

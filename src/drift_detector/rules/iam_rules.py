"""Scoped policy heuristics. No claim of complete effective-permission evaluation."""

import fnmatch

from drift_detector.baseline.normalizers import as_list, stable
from drift_detector.models import Resource
from drift_detector.rules.catalog import finding

MUTATION = {
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:updateassumerolepolicy",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:createaccesskey",
    "iam:addusertogroup",
}
WORKLOAD = {
    "lambda:createfunction",
    "lambda:updatefunctionconfiguration",
    "ec2:runinstances",
    "ecs:registertaskdefinition",
    "glue:createdevendpoint",
    "cloudformation:createstack",
}
GLOBAL_READS = {
    "ec2:describe*",
    "cloudtrail:lookupevents",
    "sts:getcalleridentity",
    "s3:listallmybuckets",
    "iam:listroles",
    "iam:listpolicies",
    "iam:listusers",
    "iam:listgroups",
}


def permits(patterns: list[str], candidates: set[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(action, pattern) for pattern in patterns for action in candidates
    )


def principals(document: dict) -> set[str]:
    values = set()
    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        for key in ("Principal", "NotPrincipal"):
            principal = statement.get(key, {})
            if isinstance(principal, dict):
                values.update(
                    stable({kind: item})
                    for kind, group in principal.items()
                    for item in as_list(group)
                )
            elif principal:
                values.update(stable(item) for item in as_list(principal))
    return values


def broad_trust(document: dict) -> bool:
    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal", {})
        if "NotPrincipal" in statement or principal == "*":
            return True
        values = (
            [item for group in principal.values() for item in as_list(group)]
            if isinstance(principal, dict)
            else as_list(principal)
        )
        if any(isinstance(item, str) and ("*" in item or "?" in item) for item in values):
            return True
    return False


def analyze_permissions(resource: Resource, old: dict, new: dict, label: str) -> list:
    result = []
    statements = [
        s
        for s in new.get("Statement", [])
        if s.get("Effect") == "Allow" and s not in old.get("Statement", [])
    ]
    all_actions = [
        action
        for s in new.get("Statement", [])
        if s.get("Effect") == "Allow"
        for action in s.get("Action", [])
    ]
    for statement in statements:

        def add(rule, statement=statement):
            result.append(
                finding(
                    rule,
                    resource,
                    {"policy": label, "document": old},
                    {"policy": label, "statement": statement},
                )
            )

        actions = statement.get("Action", [])
        if any("*" in action or "?" in action for action in actions):
            add("IAM_WILDCARD_ACTION")
        resources = statement.get("Resource", [])
        all_unscopable_reads = actions and all(
            any(fnmatch.fnmatchcase(a, p) for p in GLOBAL_READS) for a in actions
        )
        if "*" in resources and not all_unscopable_reads:
            add("IAM_WILDCARD_RESOURCE")
        if "NotAction" in statement or "NotResource" in statement:
            add("IAM_NEGATED_ALLOW")
        escalation = permits(actions, MUTATION)
        escalation |= (
            permits(all_actions, {"iam:passrole"})
            and permits(all_actions, WORKLOAD)
            and (permits(actions, {"iam:passrole"}) or permits(actions, WORKLOAD))
        )
        escalation |= permits(actions, {"sts:assumerole"}) and any("*" in r for r in resources)
        if escalation:
            add("IAM_PRIVILEGE_ESCALATION_RISK")
    return result


def evaluate(resource: Resource, actual: dict) -> list:
    expected = resource.expected
    result = []
    old_trust, new_trust = expected["trust_policy"], actual["trust_policy"]
    if old_trust != new_trust:
        broadened = broad_trust(new_trust) or bool(principals(new_trust) - principals(old_trust))
        result.append(
            finding(
                "IAM_TRUST_POLICY_BROADENED" if broadened else "IAM_TRUST_POLICY_CHANGED",
                resource,
                old_trust,
                new_trust,
            )
        )
    for kind in ("inline_policies", "attached_policies"):
        old, new = expected[kind], actual[kind]
        for name in sorted(old.keys() - new.keys()):
            result.append(finding("IAM_BASELINE_POLICY_REMOVED", resource, {name: old[name]}, None))
        for name, document in new.items():
            if name not in old:
                if kind == "inline_policies":
                    rule = "IAM_INLINE_POLICY_ADDED"
                elif name.endswith(":iam::aws:policy/AdministratorAccess"):
                    rule = "IAM_ADMIN_POLICY_ATTACHED"
                elif ":iam::aws:policy/" in name and (
                    "FullAccess" in name or "PowerUserAccess" in name
                ):
                    rule = "IAM_BROAD_MANAGED_POLICY"
                else:
                    rule = "IAM_UNEXPECTED_POLICY_ATTACHMENT"
                result.append(finding(rule, resource, list(old), {name: document}))
            elif old[name] != document:
                result.append(
                    finding("IAM_POLICY_CHANGED", resource, {name: old[name]}, {name: document})
                )
            result.extend(analyze_permissions(resource, old.get(name, {}), document, name))
    return result

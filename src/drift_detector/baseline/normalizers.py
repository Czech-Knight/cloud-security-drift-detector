"""Normalize unordered security properties, never operational response metadata."""

import ipaddress
import json
from typing import Any
from urllib.parse import unquote

from drift_detector.models import IAMState, S3State, SGState


def stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def unordered(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: unordered(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return sorted({stable(unordered(v)): unordered(v) for v in value}.values(), key=stable)
    return value


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def policy(document: dict | str | None) -> dict | None:
    if document is None:
        return None
    if isinstance(document, str):
        document = json.loads(unquote(document))
    if not isinstance(document, dict) or "Statement" not in document:
        raise ValueError("Policy must be an object with Statement")
    statements = []
    for item in as_list(document["Statement"]):
        if not isinstance(item, dict) or item.get("Effect") not in {"Allow", "Deny"}:
            raise ValueError("Policy statement requires Allow/Deny Effect")
        statement = {k: v for k, v in item.items() if k != "Sid"}
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in statement:
                values = as_list(statement[key])
                if not values or not all(isinstance(v, str) for v in values):
                    raise ValueError(f"Policy {key} must contain strings")
                # IAM action names are case insensitive; resource ARNs are not.
                statement[key] = [v.lower() for v in values] if "Action" in key else values
        for key in ("Principal", "NotPrincipal"):
            if key in statement and isinstance(statement[key], dict):
                statement[key] = {k: as_list(v) for k, v in statement[key].items()}
        if "Condition" in statement:
            statement["Condition"] = {
                op: {k: as_list(v) for k, v in pairs.items()}
                for op, pairs in statement["Condition"].items()
            }
        statements.append(statement)
    return unordered({"Version": document.get("Version", "2012-10-17"), "Statement": statements})


def network_rules(rules: list[dict]) -> list[dict]:
    result = []
    for raw in rules:
        item = dict(raw)
        item["protocol"] = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(
            str(item["protocol"]).lower(), str(item["protocol"]).lower()
        )
        if item["protocol"] == "-1":
            item["from_port"] = item["to_port"] = None
        if item["source_type"] in {"ipv4", "ipv6"}:
            net = ipaddress.ip_network(item["source"], strict=False)
            if (net.version == 4) != (item["source_type"] == "ipv4"):
                raise ValueError("Network family disagrees with source_type")
            item["source"] = str(net)
        if item["protocol"] in {"tcp", "udp"}:
            if not (
                isinstance(item["from_port"], int)
                and isinstance(item["to_port"], int)
                and 0 <= item["from_port"] <= item["to_port"] <= 65535
            ):
                raise ValueError("Invalid TCP/UDP port range")
        result.append(item)
    return unordered(result)


def normalize_state(resource_type: str, state: dict) -> dict:
    classes = {"s3": S3State, "security_group": SGState, "iam_role": IAMState}
    result = classes[resource_type].model_validate(state).model_dump()
    if resource_type == "iam_role":
        result["trust_policy"] = policy(result["trust_policy"])
        for key in ("inline_policies", "attached_policies"):
            result[key] = {name: policy(doc) for name, doc in result[key].items()}
    elif resource_type == "security_group":
        result = {key: network_rules(result[key]) for key in ("ingress", "egress")}
    else:
        result["policy"] = policy(result["policy"])
        result["acl"] = unordered(result["acl"])
        if result["encryption"] is not None:
            result["encryption"].setdefault("bucket_key_enabled", False)
    return unordered(result)

"""Evaluate added atomic rules; expected public HTTPS and ordering are not drift."""

import ipaddress

from drift_detector.models import Resource
from drift_detector.rules.catalog import finding

DATABASE_PORTS = {1433, 3306, 5432, 6379, 27017}


def covers(rule: dict, port: int) -> bool:
    return rule["protocol"] == "-1" or (
        rule["protocol"] in {"tcp", "udp"} and rule["from_port"] <= port <= rule["to_port"]
    )


def broader(rule: dict, baseline: list[dict]) -> bool:
    if rule["source_type"] not in {"ipv4", "ipv6"}:
        return False
    network = ipaddress.ip_network(rule["source"])
    for old in baseline:
        if all(rule[k] == old[k] for k in ("protocol", "from_port", "to_port", "source_type")):
            trusted = ipaddress.ip_network(old["source"])
            if trusted != network and trusted.subnet_of(network):
                return True
    return False


def evaluate(resource: Resource, actual: dict) -> list:
    result = []
    for direction in ("ingress", "egress"):
        expected = resource.expected[direction]
        for rule in actual[direction]:
            if rule in expected:
                continue
            public = rule["source"] in {"0.0.0.0/0", "::/0"}
            ids = []
            if direction == "egress":
                result.append(
                    finding(
                        "SG_UNEXPECTED_EGRESS",
                        resource,
                        expected,
                        rule,
                        "HIGH" if public else "MEDIUM",
                    )
                )
                continue
            if public:
                if rule["protocol"] == "-1" or (
                    rule["protocol"] in {"tcp", "udp"}
                    and rule["from_port"] == 0
                    and rule["to_port"] == 65535
                ):
                    ids.append("SG_ALL_PORTS_PUBLIC")
                else:
                    if rule["protocol"] == "tcp" and covers(rule, 22):
                        ids.append("SG_PUBLIC_SSH")
                    if rule["protocol"] == "tcp" and covers(rule, 3389):
                        ids.append("SG_PUBLIC_RDP")
                    if any(covers(rule, port) for port in DATABASE_PORTS):
                        ids.append("SG_PUBLIC_DATABASE_PORT")
                if rule["source"] == "::/0":
                    ids.append("SG_IPV6_PUBLIC_EXPOSURE")
            if not ids:
                ids = ["SG_CIDR_BROADENED" if broader(rule, expected) else "SG_UNEXPECTED_INGRESS"]
            for rule_id in ids:
                level = "HIGH" if rule_id == "SG_UNEXPECTED_INGRESS" and public else None
                result.append(finding(rule_id, resource, expected, rule, level))
    return result

"""Flatten grouped AWS permissions into independent source/protocol/port rules."""

from botocore.exceptions import ClientError

from drift_detector.models import MissingResource


def flatten_permissions(permissions: list[dict]) -> list[dict]:
    rules = []
    for permission in permissions:
        sources = []
        sources.extend(("ipv4", r["CidrIp"]) for r in permission.get("IpRanges", []))
        sources.extend(("ipv6", r["CidrIpv6"]) for r in permission.get("Ipv6Ranges", []))
        sources.extend(
            ("prefix_list", r["PrefixListId"]) for r in permission.get("PrefixListIds", [])
        )
        sources.extend(
            ("security_group", f"{r.get('UserId', '')}/{r['GroupId']}")
            for r in permission.get("UserIdGroupPairs", [])
        )
        for source_type, source in sources:
            rules.append(
                {
                    "protocol": permission["IpProtocol"],
                    "from_port": permission.get("FromPort"),
                    "to_port": permission.get("ToPort"),
                    "source_type": source_type,
                    "source": source,
                }
            )
    return rules


class SecurityGroupCollector:
    def __init__(self, client):
        self.client = client

    def collect(self, resource) -> dict:
        try:
            groups = self.client.describe_security_groups(GroupIds=[resource.id])["SecurityGroups"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidGroup.NotFound":
                raise MissingResource from exc
            raise
        if not groups:
            raise MissingResource
        return {
            "ingress": flatten_permissions(groups[0]["IpPermissions"]),
            "egress": flatten_permissions(groups[0]["IpPermissionsEgress"]),
        }

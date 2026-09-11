"""Read all inline policies and each attached managed policy's default version."""

from botocore.exceptions import ClientError

from drift_detector.baseline.normalizers import policy
from drift_detector.models import MissingResource


class IAMCollector:
    def __init__(self, client):
        self.client = client

    def collect(self, resource) -> dict:
        try:
            role = self.client.get_role(RoleName=resource.id)["Role"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                raise MissingResource from exc
            raise
        inline, attached = {}, {}
        for page in self.client.get_paginator("list_role_policies").paginate(RoleName=resource.id):
            for name in page["PolicyNames"]:
                inline[name] = policy(
                    self.client.get_role_policy(RoleName=resource.id, PolicyName=name)[
                        "PolicyDocument"
                    ]
                )
        for page in self.client.get_paginator("list_attached_role_policies").paginate(
            RoleName=resource.id
        ):
            for attachment in page["AttachedPolicies"]:
                arn = attachment["PolicyArn"]
                version = self.client.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                attached[arn] = policy(
                    self.client.get_policy_version(PolicyArn=arn, VersionId=version)[
                        "PolicyVersion"
                    ]["Document"]
                )
        return {
            "trust_policy": policy(role["AssumeRolePolicyDocument"]),
            "inline_policies": inline,
            "attached_policies": attached,
        }

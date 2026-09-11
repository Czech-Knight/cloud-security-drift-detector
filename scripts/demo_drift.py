#!/usr/bin/env python3
"""Deliberately unsafe demo mutation. Never imported by the scanner."""

import argparse
import os
import sys

from botocore.exceptions import BotoCoreError, ClientError

from drift_detector.aws.common import error_message
from drift_detector.aws.session import AWSCollector
from drift_detector.baseline.loader import load_baseline
from drift_detector.config import default_baseline, default_region
from drift_detector.models import DetectorError


def main():
    parser = argparse.ArgumentParser(
        description="Temporarily weaken ONE explicitly tagged disposable demo resource."
    )
    parser.add_argument("--scenario", choices=("ssh", "s3", "iam"), default="ssh")
    parser.add_argument("--baseline", default=default_baseline())
    parser.add_argument("--profile")
    parser.add_argument("--region", default=default_region())
    args = parser.parse_args()
    try:
        if os.getenv("I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT") != "yes":
            raise DetectorError(
                "This creates an intentionally unsafe AWS configuration. Set I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT=yes only for this disposable demo."
            )
        baseline = load_baseline(args.baseline)
        aws = AWSCollector(baseline, args.profile, args.region)
        kind = {"ssh": "security_group", "s3": "s3", "iam": "iam_role"}[args.scenario]
        resources = [r for r in baseline.resources if r.type == kind]
        if len(resources) != 1:
            raise DetectorError("Demo mutation requires exactly one resource of the selected type.")
        resource = resources[0]
        print(
            f"UNSAFE DEMO: {args.scenario} | Account {aws.account} | Region {aws.region} | {resource.id}"
        )
        if args.scenario == "ssh":
            ec2 = aws.client("ec2")
            group = ec2.describe_security_groups(GroupIds=[resource.id])["SecurityGroups"][0]
            tags = {t["Key"]: t["Value"] for t in group.get("Tags", [])}
            if tags.get("DriftDemo") != "true" or tags.get("ManagedBy") != "Terraform":
                raise DetectorError("Refusing mutation: group lacks the Terraform/DriftDemo tags.")
            interfaces = ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [resource.id]}]
            )["NetworkInterfaces"]
            if interfaces:
                raise DetectorError(
                    "Refusing public SSH: group is attached to a network interface."
                )
            ec2.authorize_security_group_ingress(
                GroupId=resource.id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0", "Description": "TEMPORARY drift detector demo"}
                        ],
                    }
                ],
            )
        elif args.scenario == "s3":
            s3 = aws.client("s3")
            tags = {
                t["Key"]: t["Value"]
                for t in s3.get_bucket_tagging(Bucket=resource.id, ExpectedBucketOwner=aws.account)[
                    "TagSet"
                ]
            }
            if tags.get("ManagedBy") != "Terraform" or tags.get("Environment") != "demo":
                raise DetectorError("Refusing mutation: bucket is not tagged as a Terraform demo.")
            settings = dict(resource.expected["public_access_block"])
            settings["BlockPublicPolicy"] = False
            s3.put_public_access_block(
                Bucket=resource.id,
                ExpectedBucketOwner=aws.account,
                PublicAccessBlockConfiguration=settings,
            )
        else:
            iam = aws.client("iam")
            role = iam.get_role(RoleName=resource.id)["Role"]
            tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
            if tags.get("ManagedBy") != "Terraform" or tags.get("Environment") != "demo":
                raise DetectorError("Refusing mutation: role is not tagged as a Terraform demo.")
            partition = resource.arn.split(":")[1]
            iam.attach_role_policy(
                RoleName=resource.id,
                PolicyArn=f"arn:{partition}:iam::aws:policy/AdministratorAccess",
            )
        print(
            "Drift created. Run python -m drift_detector scan, then terraform -chdir=terraform apply to restore. Do not leave this state in place."
        )
        return 0
    except (DetectorError, ClientError, BotoCoreError) as exc:
        print(str(exc) if isinstance(exc, DetectorError) else error_message(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

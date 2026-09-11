"""Best-effort recent related activity, never claimed as causal attribution."""

import json
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from drift_detector.aws.common import error_message


class CloudTrailCollector:
    def __init__(self, aws):
        self.aws = aws

    def enrich(self, report, resources, hours=24):
        report.warnings.append(
            "CloudTrail context is best effort: recent related write events are not proof of the cause. No event does not mean no change."
        )
        for resource in resources:
            affected = [
                f
                for f in report.findings
                if f.resource_type == resource.type and f.resource_id == resource.id
            ]
            if not affected:
                continue
            partition = resource.arn.split(":")[1]
            home = {"aws": "us-east-1", "aws-cn": "cn-north-1", "aws-us-gov": "us-gov-west-1"}.get(
                partition, self.aws.region
            )
            region = home if resource.type == "iam_role" else self.aws.region
            try:
                client = self.aws.client("cloudtrail", region=region)
                pages = client.get_paginator("lookup_events").paginate(
                    LookupAttributes=[
                        {"AttributeKey": "ResourceName", "AttributeValue": resource.id}
                    ],
                    StartTime=datetime.now(UTC) - timedelta(hours=hours),
                    PaginationConfig={"MaxItems": 100, "PageSize": 50},
                )
                events = []
                for page in pages:
                    for event in page.get("Events", []):
                        body = json.loads(event.get("CloudTrailEvent", "{}"))
                        if str(body.get("readOnly", "false")).lower() == "true" or body.get(
                            "errorCode"
                        ):
                            continue
                        events.append(
                            {
                                "label": "Possible related CloudTrail event",
                                "event_id": event.get("EventId"),
                                "event_name": event.get("EventName"),
                                "time": event["EventTime"].isoformat(),
                                "actor": body.get("userIdentity", {}).get(
                                    "arn", event.get("Username", "unknown")
                                ),
                                "source_ip": body.get("sourceIPAddress", "unknown"),
                                "region": region,
                            }
                        )
                for item in affected:
                    item.cloudtrail_events = events[:5]
            except (ClientError, BotoCoreError, ValueError, KeyError, TypeError) as exc:
                report.warnings.append(
                    f"CloudTrail unavailable for {resource.id}: {error_message(exc)}"
                )

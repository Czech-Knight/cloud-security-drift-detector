"""EventBridge-to-SQS worker: consume relevant AWS management events and rescan trusted targets."""

import json
import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from drift_detector.aws.common import error_message
from drift_detector.fleet import matching_targets, scan_fleet
from drift_detector.models import DetectorError

logger = logging.getLogger(__name__)
SOURCES = {"s3.amazonaws.com", "ec2.amazonaws.com", "iam.amazonaws.com"}


def event_account(body):
    """Only CloudTrail write events for supported services can trigger a scan."""
    event = json.loads(body)
    if not isinstance(event, dict):
        raise ValueError("SQS message is not an EventBridge object")
    if event.get("detail-type") != "AWS API Call via CloudTrail":
        return None
    detail = event.get("detail")
    if not isinstance(detail, dict):
        raise ValueError("CloudTrail event has no detail object")
    if detail.get("eventSource") not in SOURCES:
        return None
    if detail.get("readOnly") in (True, "true") or detail.get("errorCode"):
        return None
    account = event.get("account")
    if not isinstance(account, str) or len(account) != 12 or not account.isdecimal():
        raise ValueError("CloudTrail event missing a valid account ID")
    return account


def poll_events(
    inventory,
    root,
    queue_url,
    profile=None,
    fail_on="HIGH",
    once=False,
    wait=20,
    queue_region=None,
):
    """Return a one-shot exit code; retain failed/incomplete messages for SQS retry and DLQ."""
    session = boto3.Session(profile_name=profile)
    queue = (
        session.client("sqs", region_name=queue_region) if queue_region else session.client("sqs")
    )
    final_code = 0
    while True:
        try:
            batch = queue.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=wait,
                VisibilityTimeout=900,
            ).get("Messages", [])
        except (ClientError, BotoCoreError) as exc:
            raise DetectorError(f"Cannot receive drift events: {error_message(exc)}") from exc
        for message in batch:
            try:
                account = event_account(message["Body"])
            except (KeyError, TypeError, ValueError) as exc:
                # A malformed event must reach the queue's configured dead-letter queue.
                logger.error("Invalid event retained for retry/DLQ: %s", exc)
                final_code = 2
                continue
            if account is None:
                # Non-write events cannot trigger privileged cross-account AWS API reads.
                queue.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
                continue
            targets = matching_targets(inventory, account)
            if not targets:
                logger.error("Unconfigured event account %s; message retained for DLQ", account)
                final_code = 2
                continue
            result = scan_fleet(inventory, root, profile, fail_on=fail_on, targets=targets)
            print(
                json.dumps(
                    {"trigger": "cloudtrail-event", "event_id": message.get("MessageId"), **result}
                )
            )
            code = result["summary"]["exit_code"]
            if code == 2:
                logger.error("Incomplete scan for %s; event retained for retry/DLQ", account)
                final_code = 2
                continue
            if code == 1 and final_code == 0:
                final_code = 1
            # A completed scan with drift has succeeded at detection: acknowledge it.
            try:
                queue.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            except (ClientError, BotoCoreError) as exc:
                raise DetectorError(
                    f"Cannot acknowledge drift event: {error_message(exc)}"
                ) from exc
        if once:
            return final_code

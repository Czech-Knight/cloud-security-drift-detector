"""Cross-account scans using a reviewed baseline and a separate read-only role per account."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from drift_detector.aws.common import error_message
from drift_detector.aws.session import CLIENT_CONFIG, AWSCollector
from drift_detector.baseline.loader import load_baseline
from drift_detector.engine.scanner import DriftScanner
from drift_detector.models import DetectorError


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    account_id: str = Field(pattern=r"^\d{12}$")
    region: str = Field(pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
    role_arn: str = Field(pattern=r"^arn:[^:]+:iam::\d{12}:role/.+$")
    baseline_path: str = Field(min_length=1)
    external_id: str | None = None

    @model_validator(mode="after")
    def role_matches_account(self):
        if self.role_arn.split(":")[4] != self.account_id:
            raise ValueError("Target role ARN must belong to its declared AWS account")
        return self


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1]
    targets: list[Target] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_targets(self):
        keys = [(target.account_id, target.region) for target in self.targets]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate account/region in fleet inventory")
        return self


def load_inventory(path: str | Path) -> tuple[Inventory, Path]:
    source = Path(path).resolve()
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
        return Inventory.model_validate(document), source.parent
    except (OSError, ValueError, TypeError, ValidationError) as exc:
        raise DetectorError(f"Invalid fleet inventory {source}: {exc}") from exc


def matching_targets(inventory: Inventory, account_id: str, region: str | None = None):
    return [
        target
        for target in inventory.targets
        if target.account_id == account_id and (region is None or target.region == region)
    ]


def scan_target(target: Target, root: Path, profile=None, resource_type=None, cloudtrail=None):
    """Never trust inventory identity alone: compare the baseline AND STS caller identity."""
    baseline = load_baseline(root / target.baseline_path)
    if (baseline.aws_account_id, baseline.aws_region) != (target.account_id, target.region):
        raise DetectorError("Target account/region disagrees with its reviewed baseline")
    session = boto3.Session(profile_name=profile, region_name=target.region)
    arguments = {"RoleArn": target.role_arn, "RoleSessionName": "drift-detector-scan"}
    if target.external_id is not None:
        arguments["ExternalId"] = target.external_id
    credentials = session.client("sts", config=CLIENT_CONFIG).assume_role(**arguments)[
        "Credentials"
    ]
    assumed = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=target.region,
    )
    aws = AWSCollector(baseline, session=assumed)
    if cloudtrail is None:
        cloudtrail = baseline.cloudtrail_enabled
    if cloudtrail:
        from drift_detector.aws.cloudtrail import CloudTrailCollector

        context = CloudTrailCollector(aws)
    else:
        context = None
    return DriftScanner(baseline, aws).scan(resource_type, context)


def scan_fleet(
    inventory: Inventory,
    root: Path,
    profile=None,
    resource_type=None,
    cloudtrail=None,
    fail_on="HIGH",
    targets=None,
):
    selected = inventory.targets if targets is None else targets
    if not selected:
        raise DetectorError("No inventory targets match the selected event/account")
    results = []
    failed = False
    crossed = False
    total_findings = 0
    total_changes = 0
    for target in selected:
        record = {"account_id": target.account_id, "region": target.region}
        try:
            report = scan_target(target, root, profile, resource_type, cloudtrail)
            record["report"] = report.to_dict()
            total_findings += len(report.findings)
            total_changes += len(report.changes)
            if report.errors:
                failed = True
            if report.exit_code(fail_on) == 1:
                crossed = True
        except (DetectorError, ClientError, BotoCoreError, OSError, ValueError) as exc:
            record["error"] = error_message(exc) if isinstance(exc, ClientError) else str(exc)
            failed = True
        results.append(record)
    exit_code = 2 if failed else 1 if crossed else 0
    return {
        "schema_version": 1,
        "scanned_at": datetime.now(UTC).isoformat(),
        "summary": {
            "status": "incomplete" if failed else "drift" if total_findings else "clean",
            "targets_selected": len(selected),
            "targets_checked": sum("report" in result for result in results),
            "findings": total_findings,
            "configuration_drift": total_changes,
            "exit_code": exit_code,
            "fail_on": fail_on,
        },
        "targets": results,
    }

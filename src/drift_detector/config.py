"""Shared live-scan entrypoint and small environment configuration surface."""

import os

from drift_detector.aws.cloudtrail import CloudTrailCollector
from drift_detector.aws.session import AWSCollector
from drift_detector.baseline.loader import load_baseline
from drift_detector.engine.scanner import DriftScanner


def default_baseline():
    return os.getenv("DRIFT_BASELINE_PATH", ".baseline/security_baseline.json")


def default_region():
    return (
        os.getenv("DRIFT_AWS_REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    )


def live_scan(path, profile=None, region=None, resource_type=None, cloudtrail=None):
    baseline = load_baseline(path)
    aws = AWSCollector(baseline, profile=profile, region=region)
    if cloudtrail is None:
        setting = os.getenv("DRIFT_ENABLE_CLOUDTRAIL")
        cloudtrail = (
            setting.lower() in {"true", "1", "yes"}
            if setting is not None
            else baseline.cloudtrail_enabled
        )
    return DriftScanner(baseline, aws).scan(
        resource_type, CloudTrailCollector(aws) if cloudtrail else None
    )

"""Shared service layer for CLI, demo, tests and the local web interface."""

import logging

from botocore.exceptions import BotoCoreError, ClientError

from drift_detector.aws.common import error_message
from drift_detector.baseline.normalizers import normalize_state, stable
from drift_detector.engine.comparator import compare
from drift_detector.models import SEVERITIES, DetectorError, MissingResource, ScanReport
from drift_detector.rules.catalog import finding

logger = logging.getLogger(__name__)


class DriftScanner:
    def __init__(self, baseline, collector):
        self.baseline, self.collector = baseline, collector

    def scan(self, resource_type=None, cloudtrail=None, mode="live"):
        selected = [
            r for r in self.baseline.resources if resource_type is None or r.type == resource_type
        ]
        if not selected:
            raise DetectorError(
                "No monitored resources match this selection. Check the baseline and --resource option."
            )
        report = ScanReport(
            self.baseline.aws_account_id,
            self.baseline.aws_region,
            mode=mode,
            resources_selected=len(selected),
        )
        for resource in selected:
            try:
                actual = normalize_state(resource.type, self.collector.collect(resource))
                changes, findings = compare(resource, actual)
                report.changes.extend(changes)
                report.findings.extend(findings)
                report.resources_checked += 1
            except MissingResource:
                report.resources_checked += 1
                report.changes.append(
                    {
                        "resource_type": resource.type,
                        "resource_id": resource.id,
                        "property": "existence",
                        "expected": True,
                        "actual": False,
                    }
                )
                report.findings.append(
                    finding("RESOURCE_MISSING", resource, resource.expected, None)
                )
            except (ClientError, BotoCoreError, ValueError, KeyError, TypeError, IndexError) as exc:
                logger.debug("Collection failed for %s", resource.id, exc_info=True)
                report.errors.append(
                    {
                        "resource_type": resource.type,
                        "resource_id": resource.id,
                        "message": error_message(exc),
                    }
                )
        report.findings.sort(
            key=lambda f: (-SEVERITIES[f.severity], f.resource_id, f.rule_id, stable(f.actual))
        )
        if cloudtrail:
            cloudtrail.enrich(report, selected)
        return report

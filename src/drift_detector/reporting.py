import json
from pathlib import Path

from drift_detector.models import SEVERITIES


def report_view(report, severity=None):
    data = report.to_dict()
    if severity:
        data["findings"] = [
            f for f in data["findings"] if SEVERITIES[f["severity"]] >= SEVERITIES[severity.upper()]
        ]
    data["summary"]["displayed_findings"] = len(data["findings"])
    return data


def console_report(report, severity=None):
    data = report_view(report, severity)
    summary = data["summary"]
    lines = [
        "Cloud Security Drift Detector",
        f"Mode: {report.mode}",
        f"AWS Account: {report.aws_account_id} | Region: {report.aws_region}",
        f"Resources checked: {report.resources_checked}/{report.resources_selected}",
        f"Configuration drift: {len(report.changes)} | Security findings: {len(report.findings)}",
        f"Scan status: {summary['status'].upper()}",
    ]
    if not report.findings and not report.errors:
        lines.append("No security drift detected within the selected scope and implemented rules.")
    for issue in report.errors:
        lines.append(f"ERROR {issue['resource_id']}: {issue['message']}")
    for warning in report.warnings:
        lines.append(f"WARNING: {warning}")
    for item in data["findings"]:
        lines.extend(
            [
                "",
                f"[{item['severity']}] {item['rule_id']}",
                item["title"],
                f"Resource: {item['resource_id']} ({item['resource_arn']})",
                "Expected:\n" + json.dumps(item["expected"], indent=2),
                "Current:\n" + json.dumps(item["actual"], indent=2),
                "Why this matters: " + item["explanation"],
                "Remediation: " + item["remediation"],
            ]
        )
        for event in item["cloudtrail_events"]:
            lines.append("Possible related CloudTrail event: " + json.dumps(event))
    if summary["displayed_findings"] != summary["findings"]:
        lines.append(
            f"\nShowing {summary['displayed_findings']} of {summary['findings']} findings; display filters do not alter the exit threshold."
        )
    return "\n".join(lines)


def emit(report, output_format="text", output_path=None, severity=None):
    data = report_view(report, severity)
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(data, indent=2) if output_format == "json" else console_report(report, severity)
    )

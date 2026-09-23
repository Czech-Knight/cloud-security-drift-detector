"""CLI is the primary interface. Exit 0 clean, 1 threshold reached, 2 incomplete/error."""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from drift_detector import __version__
from drift_detector.baseline.builder import build_baseline
from drift_detector.baseline.loader import save_baseline
from drift_detector.config import default_baseline, default_region, live_scan
from drift_detector.models import SEVERITIES, DetectorError
from drift_detector.reporting import emit


def parser():
    root = argparse.ArgumentParser(
        description="Compare AWS security settings with a trusted Terraform baseline."
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("baseline", "scan", "demo", "serve"):
        cmd = commands.add_parser(name)
        cmd.add_argument(
            "--debug",
            action="store_true",
            help="Show application stack traces; SDK debug logging stays disabled",
        )
        if name != "demo":
            cmd.add_argument("--baseline", default=default_baseline())
            cmd.add_argument("--profile", help="AWS shared-config profile (SSO supported)")
            cmd.add_argument("--region", default=default_region())
        if name in {"scan", "demo"}:
            cmd.add_argument("--format", choices=("text", "json"), default="text")
            cmd.add_argument("--json", dest="format", action="store_const", const="json")
            cmd.add_argument("--output", help="Also save JSON report to this path")
            cmd.add_argument("--resource", choices=("s3", "security_group", "iam_role"))
            cmd.add_argument(
                "--severity", type=str.upper, choices=SEVERITIES, help="Minimum displayed severity"
            )
            cmd.add_argument("--fail-on", type=str.upper, choices=SEVERITIES, default="INFO")
        if name in {"scan", "serve"}:
            cmd.add_argument("--cloudtrail", action=argparse.BooleanOptionalAction, default=None)
        if name == "baseline":
            cmd.add_argument("--terraform-dir", default="terraform")
            cmd.add_argument(
                "--terraform-output", help="Saved full terraform output -json document"
            )
            cmd.add_argument("--force", action="store_true")
            cmd.add_argument(
                "--skip-live-verification",
                action="store_true",
                help="Trust Terraform outputs without checking AWS; intended for explicitly reviewed offline exports",
            )
        if name == "demo":
            cmd.add_argument("--clean", action="store_true")
        if name == "serve":
            cmd.add_argument("--demo", action="store_true", help="Use offline fixtures only")
            cmd.add_argument("--port", type=int, default=8787)
    fleet = commands.add_parser("fleet", help="Scan reviewed baselines in multiple AWS accounts")
    fleet.add_argument("--inventory", required=True)
    fleet.add_argument("--profile")
    fleet.add_argument("--resource", choices=("s3", "security_group", "iam_role"))
    fleet.add_argument("--fail-on", type=str.upper, choices=SEVERITIES, default="HIGH")
    fleet.add_argument("--cloudtrail", action=argparse.BooleanOptionalAction, default=None)
    fleet.add_argument("--output")
    fleet.add_argument("--debug", action="store_true")

    events = commands.add_parser("events", help="Scan on EventBridge-to-SQS CloudTrail write events")
    events.add_argument("--inventory", required=True)
    events.add_argument("--queue-url", required=True)
    events.add_argument("--profile")
    events.add_argument("--fail-on", type=str.upper, choices=SEVERITIES, default="HIGH")
    events.add_argument("--once", action="store_true", help="Poll one SQS batch, then exit")
    events.add_argument("--poll-seconds", type=int, default=20)
    events.add_argument("--debug", action="store_true")

    remediation = commands.add_parser("remediate", help="Review and apply a saved Terraform plan")
    steps = remediation.add_subparsers(dest="remediation_step", required=True)
    for step in ("plan", "apply"):
        command = steps.add_parser(step)
        command.add_argument("--baseline", default=default_baseline())
        command.add_argument("--terraform-dir", default="terraform")
        command.add_argument("--plan-path", default=".remediation/reconcile.tfplan")
        command.add_argument("--profile")
        command.add_argument("--debug", action="store_true")
        if step == "apply":
            command.add_argument("--approved-plan-sha256", required=True)
            command.add_argument("--approval-ticket", required=True)
            command.add_argument("--approved-by", required=True)
            command.add_argument("--confirm-apply", action="store_true", required=True)

    return root


def main(argv=None):
    args = parser().parse_args(argv)
    level = "DEBUG" if args.debug else os.getenv("DRIFT_LOG_LEVEL", "WARNING").upper()
    logging.basicConfig(level=getattr(logging, level, logging.WARNING), stream=sys.stderr)
    for name in ("botocore", "boto3", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        if args.command in {"fleet", "events"}:
            from drift_detector.fleet import load_inventory, scan_fleet

            inventory, directory = load_inventory(args.inventory)
            if args.command == "events":
                from drift_detector.events import poll_events

                if not 0 <= args.poll_seconds <= 20:
                    raise DetectorError("SQS poll seconds must be between 0 and 20")
                return poll_events(
                    inventory, directory, args.queue_url, args.profile,
                    args.fail_on, args.once, args.poll_seconds,
                )
            result = scan_fleet(
                inventory, directory, args.profile, args.resource,
                args.cloudtrail, args.fail_on,
            )
            serialized = json.dumps(result, indent=2)
            if args.output:
                path = Path(args.output)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(serialized + "\n", encoding="utf-8")
            print(serialized)
            return result["summary"]["exit_code"]
        if args.command == "remediate":
            from drift_detector.remediation import apply_approved_plan, plan_reconciliation

            if args.remediation_step == "plan":
                result = plan_reconciliation(
                    args.baseline, args.terraform_dir, args.plan_path, args.profile
                )
            else:
                if not args.confirm_apply:
                    raise DetectorError("Explicit --confirm-apply is required")
                result = apply_approved_plan(
                    args.baseline, args.terraform_dir, args.plan_path,
                    args.approved_plan_sha256, args.approval_ticket,
                    args.approved_by, args.profile,
                )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "baseline":
            if Path(args.baseline).exists() and not args.force:
                raise DetectorError(
                    "Baseline already exists. Review intended Terraform changes and use --force to replace it."
                )
            baseline = build_baseline(args.terraform_dir, args.terraform_output)
            print(
                f"Trust source: Terraform output | Account: {baseline.aws_account_id} | Region: {baseline.aws_region}"
            )
            for resource in baseline.resources:
                print(f"  {resource.type}: {resource.id}")
            if not args.skip_live_verification:
                from drift_detector.aws.session import AWSCollector
                from drift_detector.engine.scanner import DriftScanner

                check = DriftScanner(
                    baseline, AWSCollector(baseline, args.profile, args.region)
                ).scan()
                if check.errors or check.changes:
                    emit(check)
                    raise DetectorError(
                        "Baseline was not saved: live state differs or could not be fully read. Restore Terraform intent and retry; never accept unexplained drift."
                    )
            else:
                print(
                    "WARNING: live verification skipped. This trusts the supplied Terraform output, not a verified AWS snapshot."
                )
            save_baseline(baseline, args.baseline, args.force)
            print(
                f"Baseline saved: {args.baseline}. Protect this file and its Terraform source from unauthorized edits."
            )
            return 0
        if args.command == "serve":
            try:
                from drift_detector.web.app import create_app
            except ImportError as exc:
                raise DetectorError(
                    'Local UI dependency missing. Install with: python -m pip install -e ".[web]"'
                ) from exc
            if not 1024 <= args.port <= 65535:
                raise DetectorError("Choose a local port between 1024 and 65535.")
            app = create_app(args.baseline, args.profile, args.region, args.demo, args.cloudtrail)
            print(
                f"Local UI: http://127.0.0.1:{args.port} ({'offline demo' if args.demo else 'live AWS'})"
            )
            app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
            return 0
        if args.command == "demo":
            from drift_detector.demo import run_demo

            report = run_demo(args.clean, args.resource)
        else:
            report = live_scan(
                args.baseline, args.profile, args.region, args.resource, args.cloudtrail
            )
        emit(report, args.format, args.output, args.severity)
        return report.exit_code(args.fail_on)
    except (DetectorError, OSError) as exc:
        if args.debug:
            logging.getLogger(__name__).exception("Command failed")
        if getattr(args, "format", None) == "json":
            failure = {
                "schema_version": 1,
                "summary": {"status": "error", "findings": 0, "errors": 1},
                "findings": [],
                "errors": [{"message": str(exc)}],
            }
            print(json.dumps(failure))
            if getattr(args, "output", None):
                try:
                    path = Path(args.output)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
                except OSError:
                    pass
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 2

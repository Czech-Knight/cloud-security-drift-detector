"""Explicit, hash-bound Terraform reconciliation; never invoked by the scan or event worker."""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import boto3

from drift_detector.baseline.loader import load_baseline
from drift_detector.config import live_scan
from drift_detector.models import DetectorError

SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _run(arguments, timeout):
    try:
        completed = subprocess.run(
            arguments, text=True, capture_output=True, check=False, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DetectorError(f"Terraform command could not complete: {exc}") from exc
    if completed.returncode:
        raise DetectorError(
            "Terraform failed (exit "
            + str(completed.returncode)
            + "): "
            + (completed.stderr or completed.stdout)[-2000:]
        )
    return completed.stdout


def _verify_context(baseline, terraform_dir, profile):
    if profile is not None and (
        os.getenv("AWS_PROFILE") != profile
        or any(os.getenv(key) for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"))
    ):
        raise DetectorError(
            "Set AWS_PROFILE to the chosen provisioner profile and unset static/temporary AWS "
            "credential environment variables before Terraform; CLI --profile alone does not "
            "select Terraform provider credentials"
        )
    current = boto3.Session(profile_name=profile, region_name=baseline.aws_region)
    account = current.client("sts").get_caller_identity()["Account"]
    if account != baseline.aws_account_id:
        raise DetectorError("Provisioner AWS account does not match the approved baseline")
    workspace = _run(["terraform", f"-chdir={terraform_dir}", "workspace", "show"], 60).strip()
    if workspace != baseline.terraform_workspace:
        raise DetectorError("Terraform workspace does not match the approved baseline")


def _verify_saved_plan_scope(baseline, terraform_dir, plan):
    """Refuse a saved plan that would switch the monitored account, region or workspace."""
    try:
        document = json.loads(
            _run(["terraform", f"-chdir={terraform_dir}", "show", "-json", str(plan)], 120)
        )
        intended = document["planned_values"]["outputs"]["security_baseline"]["value"]
        if (
            intended["aws_account_id"] != baseline.aws_account_id
            or intended["aws_region"] != baseline.aws_region
            or intended["terraform_workspace"] != baseline.terraform_workspace
        ):
            raise DetectorError("Saved plan changes the reviewed AWS account/region/workspace")
    except (KeyError, TypeError, ValueError) as exc:
        raise DetectorError("Cannot verify Terraform saved-plan account/region/workspace") from exc


def _paths(baseline_path, terraform_dir, plan_path):
    baseline = load_baseline(baseline_path)
    directory = Path(terraform_dir).resolve()
    if not directory.is_dir():
        raise DetectorError("Terraform directory does not exist")
    plan = Path(plan_path).resolve()
    return baseline, directory, plan


def plan_reconciliation(baseline_path, terraform_dir, plan_path, profile=None):
    baseline, directory, plan = _paths(baseline_path, terraform_dir, plan_path)
    _verify_context(baseline, directory, profile)
    if plan.exists():
        raise DetectorError("Refusing to overwrite an existing reviewed/saved plan")
    plan.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _run(
        ["terraform", f"-chdir={directory}", "plan", "-input=false", "-lock=true", f"-out={plan}"],
        600,
    )
    if not plan.is_file():
        raise DetectorError("Terraform did not produce the requested plan")
    plan.chmod(0o600)
    _verify_saved_plan_scope(baseline, directory, plan)
    checksum = hashlib.sha256(plan.read_bytes()).hexdigest()
    return {
        "plan_path": str(plan),
        "plan_sha256": checksum,
        "review_command": f"terraform -chdir={directory} show {plan}",
        "account_id": baseline.aws_account_id,
        "region": baseline.aws_region,
        "workspace": baseline.terraform_workspace,
    }


def apply_approved_plan(
    baseline_path,
    terraform_dir,
    plan_path,
    approved_sha256,
    approval_ticket,
    approved_by,
    profile=None,
):
    """Approval is organizational/external: this verifies a plan hash and operator attestation."""
    baseline, directory, plan = _paths(baseline_path, terraform_dir, plan_path)
    if not SHA256.fullmatch(approved_sha256):
        raise DetectorError("Supply the exact 64-character approved plan SHA-256")
    if not approval_ticket.strip() or not approved_by.strip():
        raise DetectorError("An external approval ticket and approver identity are required")
    if not plan.is_file() or hashlib.sha256(plan.read_bytes()).hexdigest() != approved_sha256:
        raise DetectorError("Saved Terraform plan does not match the approved SHA-256")
    _verify_context(baseline, directory, profile)
    _verify_saved_plan_scope(baseline, directory, plan)
    _run(["terraform", f"-chdir={directory}", "apply", "-input=false", str(plan)], 900)
    # Never rebaseline as remediation; a post-apply scan must match original intent.
    report = live_scan(baseline_path, profile, baseline.aws_region)
    if report.errors or report.changes:
        raise DetectorError(
            "Terraform apply completed, but post-apply drift verification is not clean; "
            "investigate before closing the approval ticket"
        )
    return {
        "status": "verified_clean",
        "account_id": baseline.aws_account_id,
        "region": baseline.aws_region,
        "plan_sha256": approved_sha256,
        "approval_ticket": approval_ticket,
        "approved_by": approved_by,
    }

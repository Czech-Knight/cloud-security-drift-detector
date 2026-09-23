"""Fleet isolation, event acknowledgment and approval-gated reconciliation tests."""

import hashlib
import json

import pytest
from pydantic import ValidationError

from drift_detector.baseline.loader import save_baseline
from drift_detector.demo import run_demo
from drift_detector.events import event_account, poll_events
from drift_detector.fleet import Inventory, Target, load_inventory, scan_fleet, scan_target
from drift_detector.models import DetectorError
from drift_detector.remediation import apply_approved_plan, plan_reconciliation


def _target(account="123456789012", region="ap-southeast-2"):
    return Target(
        account_id=account,
        region=region,
        role_arn=f"arn:aws:iam::{account}:role/drift-read-only",
        baseline_path="approved.json",
    )


def test_fleet_validates_target_identity_and_duplicate_regions(tmp_path, baseline):
    save_baseline(baseline, tmp_path / "approved.json")
    wrong = _target(account="999999999999")
    with pytest.raises(DetectorError, match="disagrees"):
        scan_target(wrong, tmp_path)
    with pytest.raises(ValidationError, match="Duplicate"):
        Inventory(schema_version=1, targets=[_target(), _target()])
    with pytest.raises(ValidationError, match="role ARN"):
        Target(
            account_id="123456789012",
            region="ap-southeast-2",
            role_arn="arn:aws:iam::999999999999:role/drift",
            baseline_path="approved.json",
        )


def test_load_inventory_rejects_bad_json(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text('{"schema_version":1,"targets":[]}')
    with pytest.raises(DetectorError, match="Invalid fleet"):
        load_inventory(path)


def test_fleet_scans_all_accounts_and_does_not_hide_failures(tmp_path, monkeypatch):
    inventory = Inventory(schema_version=1, targets=[_target(), _target("999999999999")])

    def fake_scan(target, *_args, **_kwargs):
        if target.account_id == "999999999999":
            raise DetectorError("AssumeRole access denied")
        return run_demo()

    monkeypatch.setattr("drift_detector.fleet.scan_target", fake_scan)
    result = scan_fleet(inventory, tmp_path)
    assert result["summary"]["targets_checked"] == 1
    assert result["summary"]["exit_code"] == 2
    assert result["targets"][1]["error"] == "AssumeRole access denied"
    assert result["targets"][0]["report"]["summary"]["findings"] >= 1


def test_completed_fleet_drift_reaches_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr("drift_detector.fleet.scan_target", lambda *_args, **_kwargs: run_demo())
    result = scan_fleet(Inventory(schema_version=1, targets=[_target()]), tmp_path)
    assert result["summary"]["exit_code"] == 1
    assert result["summary"]["status"] == "drift"


def _event(account="123456789012", readonly=False, source="ec2.amazonaws.com"):
    return json.dumps(
        {
            "detail-type": "AWS API Call via CloudTrail",
            "account": account,
            "region": "ap-southeast-2",
            "detail": {
                "eventSource": source,
                "eventName": "AuthorizeSecurityGroupIngress",
                "readOnly": readonly,
            },
        }
    )


def test_only_relevant_successful_write_events_trigger():
    assert event_account(_event()) == "123456789012"
    assert event_account(_event(readonly=True)) is None
    assert (
        event_account(
            _event(source="ec2.amazonaws.com").replace(
                '"readOnly": false', '"errorCode": "AccessDenied", "readOnly": false'
            )
        )
        is None
    )
    assert event_account(_event(source="lambda.amazonaws.com")) is None
    with pytest.raises(ValueError, match="valid account"):
        event_account(_event(account="not-an-account"))


def test_event_worker_acks_completed_drift_but_retains_incomplete(monkeypatch, tmp_path):
    class Queue:
        def __init__(self):
            self.messages = [{"Body": _event(), "ReceiptHandle": "receipt", "MessageId": "evt"}]
            self.acknowledged = []

        def receive_message(self, **_kwargs):
            return {"Messages": self.messages}

        def delete_message(self, **kwargs):
            self.acknowledged.append(kwargs["ReceiptHandle"])

    queue = Queue()

    class Session:
        def client(self, name):
            assert name == "sqs"
            return queue

    monkeypatch.setattr("drift_detector.events.boto3.Session", lambda **_kwargs: Session())
    results = iter([1, 2])

    def scan(*_args, **_kwargs):
        return {"summary": {"exit_code": next(results)}}

    monkeypatch.setattr("drift_detector.events.scan_fleet", scan)
    inventory = Inventory(schema_version=1, targets=[_target()])
    assert poll_events(inventory, tmp_path, "https://example.test/queue", once=True, wait=0) == 1
    assert queue.acknowledged == ["receipt"]
    queue.acknowledged.clear()
    assert poll_events(inventory, tmp_path, "https://example.test/queue", once=True, wait=0) == 2
    assert queue.acknowledged == []


def test_plan_and_apply_require_exact_reviewed_bytes(tmp_path, baseline, monkeypatch):
    base = tmp_path / "approved.json"
    save_baseline(baseline, base)
    directory = tmp_path / "terraform"
    directory.mkdir()
    path = tmp_path / ".remediation" / "fix.tfplan"
    monkeypatch.setattr("drift_detector.remediation._verify_context", lambda *_args: None)
    commands = []

    def terraform(arguments, _timeout):
        commands.append(arguments)
        for argument in arguments:
            if argument.startswith("-out="):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"reviewed terraform plan")
        return ""

    monkeypatch.setattr("drift_detector.remediation._run", terraform)
    result = plan_reconciliation(base, directory, path)
    assert result["plan_sha256"] == hashlib.sha256(b"reviewed terraform plan").hexdigest()
    with pytest.raises(DetectorError, match="existing"):
        plan_reconciliation(base, directory, path)
    with pytest.raises(DetectorError, match="does not match"):
        apply_approved_plan(base, directory, path, "0" * 64, "CHG-123", "Reviewer")
    assert len(commands) == 1

    class CleanReport:
        errors = []
        changes = []

    monkeypatch.setattr("drift_detector.remediation.live_scan", lambda *_args: CleanReport())
    verified = apply_approved_plan(
        base, directory, path, result["plan_sha256"], "CHG-123", "Reviewer"
    )
    assert verified["status"] == "verified_clean"
    assert commands[-1][-1] == str(path)


def test_apply_failure_does_not_rebaseline(tmp_path, baseline, monkeypatch):
    base = tmp_path / "approved.json"
    save_baseline(baseline, base)
    directory = tmp_path / "tf"
    directory.mkdir()
    plan = tmp_path / "file.tfplan"
    plan.write_bytes(b"plan")
    monkeypatch.setattr("drift_detector.remediation._verify_context", lambda *_args: None)
    monkeypatch.setattr("drift_detector.remediation._run", lambda *_args: "")

    class Drift:
        errors = []
        changes = [{"property": "ingress"}]

    monkeypatch.setattr("drift_detector.remediation.live_scan", lambda *_args: Drift())
    with pytest.raises(DetectorError, match="not clean"):
        apply_approved_plan(
            base,
            directory,
            plan,
            hashlib.sha256(b"plan").hexdigest(),
            "CHG-456",
            "Reviewer",
        )

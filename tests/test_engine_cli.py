import json
from copy import deepcopy

import pytest
from botocore.exceptions import ClientError

from drift_detector.baseline.builder import build_baseline
from drift_detector.baseline.loader import digest, load_baseline, save_baseline
from drift_detector.cli import main
from drift_detector.demo import FixtureCollector, demo_inputs, run_demo
from drift_detector.engine.scanner import DriftScanner
from drift_detector.models import DetectorError


def test_demo_scenario_counts_and_exit():
    report = run_demo()
    assert report.resources_checked == 3
    assert {"SG_PUBLIC_SSH", "IAM_ADMIN_POLICY_ATTACHED", "S3_PUBLIC_ACCESS_BLOCK_DISABLED"} <= {
        f.rule_id for f in report.findings
    }
    assert report.exit_code() == 1
    assert run_demo(True).exit_code() == 0


def test_removed_ingress_is_config_delta_without_exposure(baseline):
    states = {f"{r.type}:{r.id}": deepcopy(r.expected) for r in baseline.resources}
    sg = next(r for r in baseline.resources if r.type == "security_group")
    states[f"security_group:{sg.id}"]["ingress"] = []
    report = DriftScanner(baseline, FixtureCollector(states)).scan()
    assert len(report.changes) == 1 and not report.findings


def test_deleted_resource_and_incomplete_access_are_distinct(baseline):
    class Collector:
        def collect(self, resource):
            if resource.type == "s3":
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetBucketAcl")
            from drift_detector.models import MissingResource

            raise MissingResource

    report = DriftScanner(baseline, Collector()).scan()
    assert report.exit_code() == 2
    assert len(report.errors) == 1 and report.resources_checked == 2
    assert len(report.findings) == 2
    assert report.to_dict()["summary"]["status"] == "incomplete"


def test_malformed_live_state_does_not_show_clean(baseline):
    class BadCollector:
        def collect(self, resource):
            return {}

    report = DriftScanner(baseline, BadCollector()).scan()
    assert len(report.errors) == 3
    assert report.exit_code() == 2


def test_baseline_roundtrip_force_and_integrity(tmp_path, baseline):
    path = tmp_path / "baseline.json"
    save_baseline(baseline, path)
    assert load_baseline(path) == baseline
    with pytest.raises(DetectorError, match="already exists"):
        save_baseline(baseline, path)
    save_baseline(baseline, path, force=True)
    payload = json.loads(path.read_text())
    payload["aws_account_id"] = "999999999999"
    path.write_text(json.dumps(payload))
    with pytest.raises(DetectorError, match="integrity"):
        load_baseline(path)


@pytest.mark.parametrize(
    "mutation", ["schema", "missing_property", "empty_resources", "duplicate", "wrong_type"]
)
def test_invalid_baseline_fails_even_with_valid_checksum(tmp_path, baseline, mutation):
    doc = baseline.model_dump()
    if mutation == "schema":
        doc["schema_version"] = 9
    elif mutation == "missing_property":
        del doc["resources"][0]["expected"]["policy_public"]
    elif mutation == "empty_resources":
        doc["resources"] = []
    elif mutation == "duplicate":
        doc["resources"].append(doc["resources"][0])
    else:
        doc["resources"][0]["expected"]["policy_public"] = "false"
    doc["integrity_sha256"] = digest(doc)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(DetectorError):
        load_baseline(path)


def test_builder_output_contract():
    built = build_baseline(output_file="examples/terraform-output.json")
    assert built.aws_account_id == "123456789012"
    assert len(built.resources) == 3


def test_baseline_refuses_existing_file_before_terraform(tmp_path, baseline, capsys):
    path = tmp_path / "base.json"
    save_baseline(baseline, path)
    assert main(["baseline", "--baseline", str(path)]) == 2
    assert "already exists" in capsys.readouterr().err


def test_baseline_verification_rejects_drift(tmp_path, monkeypatch, capsys):
    _, collector = demo_inputs(False)
    monkeypatch.setattr("drift_detector.aws.session.AWSCollector", lambda *a, **kw: collector)
    path = tmp_path / "baseline.json"
    assert (
        main(
            [
                "baseline",
                "--terraform-output",
                "examples/terraform-output.json",
                "--baseline",
                str(path),
            ]
        )
        == 2
    )
    assert not path.exists()


def test_baseline_verification_accepts_clean(tmp_path, monkeypatch):
    _, collector = demo_inputs(True)
    monkeypatch.setattr("drift_detector.aws.session.AWSCollector", lambda *a, **kw: collector)
    path = tmp_path / "baseline.json"
    assert (
        main(
            [
                "baseline",
                "--terraform-output",
                "examples/terraform-output.json",
                "--baseline",
                str(path),
            ]
        )
        == 0
    )
    assert load_baseline(path).aws_region == "ap-southeast-2"


def test_cli_json_pure_and_display_filter_cannot_hide_failure(capsys):
    assert main(["demo", "--format", "json", "--severity", "critical"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["displayed_findings"] == 2
    assert payload["summary"]["findings"] > 2


def test_fail_threshold_and_resource_filter(capsys):
    assert main(["demo", "--resource", "s3", "--fail-on", "critical", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] == 1
    assert data["summary"]["resources_checked"] == 1


def test_json_missing_baseline_is_error(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    assert (
        main(
            [
                "scan",
                "--baseline",
                str(tmp_path / "no.json"),
                "--json",
                "--output",
                str(report_path),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["status"] == "error"
    assert json.loads(report_path.read_text())["errors"]


def test_empty_selected_scope_is_not_clean(baseline):
    baseline.resources = [r for r in baseline.resources if r.type == "s3"]
    with pytest.raises(DetectorError, match="No monitored resources"):
        DriftScanner(baseline, FixtureCollector({})).scan("iam_role")


def test_arn_account_binding_is_validated(tmp_path, baseline):
    document = baseline.model_dump()
    document["resources"][1]["arn"] = document["resources"][1]["arn"].replace(
        "123456789012", "999999999999"
    )
    document["integrity_sha256"] = digest(document)
    path = tmp_path / "bad-arn.json"
    path.write_text(json.dumps(document))
    with pytest.raises(DetectorError):
        load_baseline(path)

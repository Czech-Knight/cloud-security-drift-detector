import re

from drift_detector.web.app import create_app


def test_local_ui_real_scan_filter_and_download():
    app = create_app("unused", demo=True)
    app.config["TESTING"] = True
    client = app.test_client()
    page = client.get("/")
    assert page.status_code == 200 and b"OFFLINE DEMO" in page.data
    csrf = re.search(rb'name="csrf" value="([^"]+)"', page.data).group(1).decode()
    assert client.post("/scan", data={}).status_code == 403
    response = client.post(
        "/scan", data={"csrf": csrf, "scenario": "drifted"}, follow_redirects=True
    )
    assert b"SG_PUBLIC_SSH" in response.data and b"IAM_ADMIN_POLICY_ATTACHED" in response.data
    report = client.get("/report.json")
    assert report.json["summary"]["critical"] == 2
    filtered = client.get("/?resource=s3&severity=HIGH")
    assert b"S3_PUBLIC_ACCESS_BLOCK_DISABLED" in filtered.data
    assert b"SG_PUBLIC_SSH" not in filtered.data
    clean = client.post("/scan", data={"csrf": csrf, "scenario": "clean"}, follow_redirects=True)
    assert b"No security findings" in clean.data
    assert client.get("/health").json["status"] == "ok"


def test_ui_missing_baseline_and_bad_host(tmp_path):
    client = create_app(str(tmp_path / "missing.json")).test_client()
    assert b"Not loaded" in client.get("/").data
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/report.json").status_code == 404

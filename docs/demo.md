# Interview demo runbook

Allow 5–10 minutes **after installation and deployment are ready**. First show the offline flow if AWS credentials or connectivity are unavailable; label it clearly as fixture data.

## Offline: two minutes

```bash
python -m drift_detector demo --clean
python -m drift_detector demo
python -m drift_detector serve --demo
```

Explain the baseline/current distinction, show one network finding, one IAM finding and one S3 guardrail finding. In the UI, run the drift scenario, filter S3, download JSON, then run the clean scenario. Exit 1 means a finding was detected. Stop with Ctrl+C.

## Live: full engineering story

1. Show `terraform/main.tf`, `outputs.tf` and the scoped read policy. Explain why expected settings use authored locals.
2. Provision with the deployer profile: `terraform -chdir=terraform init`, `plan`, then `apply`. No compute service is created.
3. Run `python -m drift_detector baseline`. Show the account, region and monitored resources.
4. Run `python -m drift_detector scan`. Expect a fully covered clean result.
5. Introduce controlled SSH drift:

```bash
I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT=yes bash scripts/demo_drift.sh
python -m drift_detector scan --resource security_group
```

6. Point out `SG_PUBLIC_SSH`, CRITICAL, TCP/22, `0.0.0.0/0`, exact expected/current values and recommended restoration. Clarify that the SG is unattached, so this demonstrates policy exposure without exposing a running server.
7. Optionally use `scan --cloudtrail` if the identity has LookupEvents permission. Say “possible related API activity,” never definite attribution.
8. Run `terraform -chdir=terraform plan`. Explain that Terraform also sees the configuration drift, while Python supplies the security interpretation.
9. Run `terraform -chdir=terraform apply`, review the changes and approve. Run the scanner against the **same original baseline** again. Expect clean.
10. Disable scheduled scans if enabled, then `terraform -chdir=terraform destroy` after reviewing cleanup.

Optional S3 and IAM scenarios are documented in [SETUP_AND_TESTING.md](../SETUP_AND_TESTING.md). Do not attach the unused role/group to workloads. Run mutations with deployer permissions, scans with read-only credentials where configured.

## Closing explanation

“I separated intended state, observed state and event context. I normalize policy documents to avoid order-only false positives, classify security-relevant changes deterministically, report incomplete reads explicitly, and leave remediation to a reviewed Terraform apply.”

Show `VALIDATION.md` and be precise about which tests were run. Do not claim the fixture demonstration is an AWS deployment, complete IAM authorization analysis or incident detection.

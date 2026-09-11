# Validation results

Validation date: **9 September 2026**. This file records observed local checks and does not claim that the project was deployed to an AWS account.

| Check | Result |
|---|---|
| Python test suite | **93 passed** on Python 3.12.14 |
| Python coverage | **90%** statement coverage (pytest-cov) |
| Ruff lint and formatting | Passed after final source formatting |
| Offline clean demo | 3/3 resources, 0 deltas/findings, exit 0 |
| Offline drift demo | 3/3 resources, 3 configuration deltas, 6 findings (2 CRITICAL, 4 HIGH), exit 1 |
| SDK response contracts | S3, EC2 and IAM tested with botocore Stubber, including IAM pagination/default versions |
| Safety and failures | Account/region mismatch, malformed baseline, ARN identity binding, corruption, overwrite refusal, AccessDenied, missing resources and empty scope tested |
| UI application routes | Actual shared scan service, clean/drifted modes, filters, report download, CSRF and Host checks tested through Flask's client |
| Terraform HCL | All 9 root `.tf` files and the mock test file parsed; Terraform formatting was applied |
| Terraform provider initialization | Initial provider installation completed; official Linux AWS provider archive checksum independently matched the generated lock file |
| Terraform native validate / mock plans | **Not completed:** a provider-cache checksum mismatch was encountered and native execution was not completed. This is not recorded as a pass. Run the documented validate/test gates in your environment before apply. |
| Wheel and source distribution | Built successfully with setuptools 82.0.1; fixtures, templates, CSS and repository source assets are packaged |
| Clean-environment wheel installation | Installed into a separate venv; outside the source directory, clean/drift/error CLI returned 0/1/2 and the UI template/CSS/scan/download checks passed |
| Documentation and scripts | Internal Markdown file links resolved; shell scripts passed Bash syntax checks |
| GitHub workflow YAML | All workflow and Dependabot YAML parsed; action SHAs resolved from official upstream repositories |
| GitHub hosted workflow execution | **Not run:** no repository was connected/published and OIDC/account settings are user-specific |
| Live AWS deployment, drift and restore | **Not run:** no AWS account credentials were supplied. Exact acceptance checks are in SETUP_AND_TESTING.md. |
| Native PowerShell / additional Python matrix | Commands and CI matrix supplied; execution here was Linux/Python 3.12 only |

## Test interpretation

Tests exercise the same normalized state schemas and security rules as real collection. SDK stubs verify call parameters and actual boto3 response shapes; the live scan path does not use fixtures. These tests do not prove that your organization's IAM/SCP controls permit deployment, that AWS APIs will be consistent immediately after apply, or that the Terraform resource graph was successfully applied in a real account.

No AWS resource was created, weakened, restored or destroyed during these checks. The separate controlled drift script was not executed against AWS.

## Required account acceptance

1. Run `terraform init`, `terraform validate` and `terraform test` successfully.
2. Confirm the intended account using STS and review the real Terraform plan.
3. Apply, generate the verified baseline, and obtain a complete clean scan.
4. Introduce controlled SSH drift; verify CRITICAL `SG_PUBLIC_SSH` and exact rule values.
5. Optionally verify the S3/IAM scenarios.
6. Apply the original Terraform configuration, then rescan the original baseline and confirm clean.
7. Destroy the demo and disable any scheduled scans.

Keep the distinction between offline proof, SDK contracts and live-cloud acceptance visible when presenting the project in a portfolio.

# Repository security automation

| Control | Trigger | Result | Enforcement |
| --- | --- | --- | --- |
| Python CI | Push/PR | Ruff, pytest, build, offline demo | Existing required status only if enabled in repository rules |
| Terraform validation | Push/PR/manual | fmt, validate and mock-provider tests | Existing required status only if enabled in repository rules |
| Static cloud assessment | Terraform PR/push, Monday, manual | Checkov JSON artifact (14 days) | Advisory baseline: triage findings before gating |
| Extended lint | Sunday/manual | MegaLinter report (7 days) | Advisory, avoids breaking older files |
| Live drift scan | Scheduled/manual AND enabled environment variable | AWS read-only scan report (7 days) | Existing severity gate; requires configured protected environment |
| Python release evidence | On published v<package-version> release | Wheel, source archive, SHA256SUMS and GitHub provenance attestation | Fails on version mismatch |

For cloud assessment, open the workflow run and download its artifact. The static scan requires no AWS credentials; live drift uses its own protected environment and role. A successful advisory job does **not** mean Checkov found zero violations.

Before enabling branch rules, run each workflow, triage existing findings, then select the actual passing required check names. Only maintainers should publish releases, and SHA256 checksums/provenance are not substitutes for verifying the publisher and release tag.

No Terraform apply, infrastructure changes, or application-code modifications are performed by the new workflows.

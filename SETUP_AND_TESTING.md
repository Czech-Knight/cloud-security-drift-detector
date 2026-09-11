# Cloud Security Drift Detector — Setup and Testing

This guide takes you from the downloaded project to a working offline demo, then a real AWS deployment, a deliberately introduced change, detection, restoration and cleanup.

**On Windows, WSL Ubuntu is recommended, with the project kept under the Linux home folder.** This avoids mixing Windows Python, WSL Python and executable permissions. You can also use native PowerShell; the alternatives are below.

The complete source, Terraform, tests, workflows and documentation are inside the ZIP.

## 1. Extract and open the correct folder

Extract `cloud-security-drift-detector.zip`. Open a terminal inside the extracted `cloud-security-drift-detector` folder. You should see `pyproject.toml`, `README.md`, `src`, `terraform` and `tests`.

For example, if you extract into your WSL home directory:

```bash
cd ~/cloud-security-drift-detector
pwd
ls
```

The exact folder location depends on where you extracted it. All following commands start from the project root.

## 2. Install Python dependencies

### WSL / Linux / macOS

Check Python first:

```bash
python3 --version
```

Use Python **3.11 or newer**. On Ubuntu, if Python or venv is missing:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
```

Create an isolated environment and install:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,web]"
python -m drift_detector --version
```

Expected version: **1.0.0**.

### Native Windows PowerShell

Install Python 3.11+ if needed, then:

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,web]"
python -m drift_detector --version
```

If PowerShell blocks activation, use the environment's interpreter directly instead of changing machine-wide policy:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web]"
.\.venv\Scripts\python.exe -m drift_detector demo --clean
```

Use that interpreter prefix for the remaining Python commands if you choose not to activate. Do not reuse a WSL-created `.venv` from PowerShell or vice versa.

**Pass check:** installation succeeds and `--version` prints `1.0.0`.

## 3. Prove the detector works without AWS

Run a clean offline scan:

```bash
python -m drift_detector demo --clean
```

Expected:

```text
Mode: offline-demo
Resources checked: 3/3
Configuration drift: 0 | Security findings: 0
Scan status: CLEAN
```

Now run the drift scenario:

```bash
python -m drift_detector demo
```

Expected: **6 findings across 3 configuration deltas**, including:

| Finding | Severity |
|---|---|
| `SG_PUBLIC_SSH` | CRITICAL |
| `IAM_ADMIN_POLICY_ATTACHED` | CRITICAL |
| `S3_PUBLIC_ACCESS_BLOCK_DISABLED` | HIGH |
| `IAM_WILDCARD_ACTION` | HIGH |
| `IAM_WILDCARD_RESOURCE` | HIGH |
| `IAM_PRIVILEGE_ESCALATION_RISK` | HIGH |

Each finding explains expected/current values, the resource, risk and remediation. Several IAM findings describe different concerns in the same newly attached policy.

Check the exit code **immediately after the detector command**:

```bash
echo $?
```

PowerShell:

```powershell
$LASTEXITCODE
```

`demo --clean` returns **0**. `demo` returns **1**, because detection succeeded. Error/incomplete scans return **2**. Do not treat exit 1 as an installation failure.

Save and inspect JSON:

```bash
python -m drift_detector demo --format json --output reports/demo.json
python -m json.tool reports/demo.json
```

The fixture is intentionally labelled `offline-demo`. Live `scan` does not fall back to fixtures if AWS access fails.

## 4. Test the local web interface

```bash
python -m drift_detector serve --demo
```

Open **http://127.0.0.1:8787** in your browser. Keep the terminal running.

1. Confirm **OFFLINE DEMO · FIXTURE DATA** and the baseline status are visible.
2. Select **Security drift** and press **Scan now**.
3. Confirm 2 CRITICAL and 4 HIGH findings appear.
4. Set Resource to **S3**, apply filters and confirm the S3 finding appears.
5. Click **Download JSON** and inspect the report.
6. Select **Clean baseline** and scan again; confirm zero findings.
7. Stop the server with **Ctrl+C**.

If the default port is busy:

```bash
python -m drift_detector serve --demo --port 8788
```

Open `http://127.0.0.1:8788` instead. The server always binds locally. No Firebase, frontend build or login setup is needed.

## 5. Run the automated tests

```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest -q
```

For coverage:

```bash
python -m pytest --cov=drift_detector --cov-report=term-missing
```

These checks use fixtures and SDK stubs; no AWS account is needed. They verify sensitive ports/ranges, IPv6, S3 settings, IAM changes, pagination, policy normalization, baseline integrity, error/exit handling, account/region checks and local UI operations.

**Pass check:** Ruff has no errors and pytest reports all tests passed. Recorded validation results and remaining environment limitations are in [VALIDATION.md](VALIDATION.md).

## 6. Prepare AWS and Terraform

Only continue here when you want to deploy to your AWS sandbox. The preceding sections already provide a working local demonstration.

Install [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and [Terraform](https://developer.hashicorp.com/terraform/install) in the same environment where you run the project. Use Terraform 1.9+ and <2; the workflow is pinned to 1.9.8 and the providers are pinned through the committed lock file.

```bash
aws --version
terraform version
```

Configure an existing authorized profile. With IAM Identity Center/SSO:

```bash
aws configure sso --profile drift-demo
aws sso login --profile drift-demo
export AWS_PROFILE=drift-demo
export AWS_DEFAULT_REGION=ap-southeast-2
aws sts get-caller-identity
```

PowerShell environment variables:

```powershell
$env:AWS_PROFILE = "drift-demo"
$env:AWS_DEFAULT_REGION = "ap-southeast-2"
aws sts get-caller-identity
```

If your account does not use SSO, use your existing profile or approved temporary credentials. `aws configure --profile drift-demo` is the standard shared-credentials alternative; do not copy access keys into project files.

**Pass check:** the account ID returned by STS is the sandbox account you intend to use.

The deployer needs permission to manage the project's S3 bucket settings, VPC/security groups and demo IAM role/policies, plus the corresponding read/delete actions. An organization administrator may need to supply this deployer role. The scanner's generated read policy is deliberately insufficient for deployment or the drift mutation script. No “AdministratorAccess for the scanner” setup is required.

Copy the configuration:

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

PowerShell:

```powershell
Copy-Item terraform/terraform.tfvars.example terraform/terraform.tfvars
```

The default values are suitable for the demo:

```hcl
aws_region         = "ap-southeast-2"
project_name       = "security-drift-demo"
trusted_admin_cidr = null
allow_public_https = false
enable_cloudtrail  = false
```

No SSH is allowed by default. To demonstrate widening a trusted source, set `trusted_admin_cidr` to your actual narrow IPv4 CIDR; `/24` through `/32` is accepted. `203.0.113.10/32` in the examples is a documentation address. Optional public HTTPS is treated as expected only when explicitly enabled.

Initialize and validate **before deploying**:

```bash
terraform -chdir=terraform init
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform validate
terraform -chdir=terraform test
```

The last command runs mocked Terraform plans. It creates no real AWS resources. Expected: **3 tests passed**, including rejection of public administrator CIDR.

Keep `.terraform.lock.hcl`. If the provider cache has a checksum mismatch, do not disable verification or manually edit hashes. Remove only the generated `.terraform` cache and re-run `terraform init` against trusted provider distribution sources. Never remove your state as a cache-repair step.

## 7. Deploy, generate baseline and prove the live state is clean

Review the real AWS plan:

```bash
terraform -chdir=terraform plan
```

Expected resources are the empty bucket and controls, tiny isolated VPC, closed default security group, unattached monitored security group, unused demo role, narrow inline policy, exclusive policy-set controls and a random naming suffix. There should be no EC2 instance, NAT gateway, database, load balancer or Kubernetes cluster.

Apply only after reviewing the plan:

```bash
terraform -chdir=terraform apply
```

Terraform prompts for `yes`. After a successful apply:

```bash
python -m drift_detector baseline
python -m drift_detector scan
```

**Pass check:** baseline creation lists the expected account/region/three monitored resources, saves `.baseline/security_baseline.json`, and scan reports **3/3 checked, zero findings, zero configuration drift**.

If a just-created resource is briefly absent or inconsistent, wait a short time for AWS propagation and retry. If it persists, inspect the named error and Terraform state. Do not use `--skip-live-verification` merely to hide an unexplained mismatch.

The baseline command refuses to overwrite an existing baseline. After a reviewed intended configuration update:

```bash
terraform -chdir=terraform plan
terraform -chdir=terraform apply
python -m drift_detector baseline --force
```

The baseline comes from authored Terraform values. It never approves a live console change just because the file is being regenerated.

To use a dedicated read-only scanner after deploying:

```bash
python scripts/export_config.py scanner-policy --output .baseline/scanner-policy.json
```

Have your account administrator attach this policy to a separate scanner role/profile. Switch to that profile for `scan`. Keep the deployer profile for `apply`, `destroy` and the explicit drift mutation script. [OIDC and permission setup](docs/github-actions.md) explains the split.

## 8. Introduce one controlled live change and detect it

Use only this disposable lab. The default mutation creates public SSH permission on the **unattached** demo group; it does not deploy a reachable SSH server.

WSL/macOS/Linux:

```bash
I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT=yes bash scripts/demo_drift.sh
python -m drift_detector scan
```

PowerShell uses the same Python implementation:

```powershell
$env:I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT = "yes"
python scripts/demo_drift.py
Remove-Item Env:I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT
python -m drift_detector scan
```

**Pass check:** `SG_PUBLIC_SSH`, severity **CRITICAL**, exact group ID, `tcp`, port `22`, source `0.0.0.0/0`, baseline ingress, explanation and remediation. Exit code is **1**.

The script checks tags and refuses the SSH mutation when an ENI uses the group. This is a preflight safeguard, not an atomic guarantee against someone attaching it concurrently. Keep this VPC unused and do not attach the group to anything during the demo.

Optional extra scenarios, using the deployer profile:

```bash
I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT=yes bash scripts/demo_drift.sh --scenario s3
python -m drift_detector scan
```

Expected: `S3_PUBLIC_ACCESS_BLOCK_DISABLED` HIGH. This removes one guardrail; it does not by itself create a public bucket policy.

```bash
I_UNDERSTAND_THIS_CREATES_SECURITY_DRIFT=yes bash scripts/demo_drift.sh --scenario iam
python -m drift_detector scan
```

Expected: `IAM_ADMIN_POLICY_ATTACHED` CRITICAL plus wildcard/escalation risk findings. This temporarily gives a broad policy to the unused demo role. Do not repurpose or attach this role to workloads, and restore promptly.

On PowerShell, set the acknowledgement variable, run `python scripts/demo_drift.py --scenario s3` or `--scenario iam`, then remove the variable as above. To present all three scenarios, you can introduce them before a single restoration; perform one at a time while learning.

## 9. Restore and verify

Use the deployer profile and the same Terraform directory/workspace:

```bash
terraform -chdir=terraform plan
terraform -chdir=terraform apply
python -m drift_detector scan
```

Or in WSL:

```bash
bash scripts/restore.sh
```

**Pass check:** the plan removes unexpected ingress/attachments and restores changed bucket settings. After apply and propagation, scan returns **3/3 checked and no findings**.

Do **not** regenerate the baseline for this restoration test. The point is to return live AWS to the original approved state.

Do not run `terraform apply -refresh-only` to remediate: that updates Terraform's recorded state instead of restoring configured security settings. Keep `terraform.tfstate` and use the original workspace.

Important boundary: Terraform restores the properties it manages here. Arbitrary changes to externally managed policy documents, unsupported object-level ACLs, or newly assumed IAM sessions can require additional response. Detaching a policy is not a complete incident-response procedure.

## 10. Clean up AWS resources

If scheduled scans were enabled, first set repository variable `DRIFT_SCAN_ENABLED=false`.

```bash
terraform -chdir=terraform plan -destroy
terraform -chdir=terraform destroy
```

**Pass check:** Terraform completes destruction. Do not delete local Terraform state before cleanup.

The bucket is empty by default. `force_destroy=false` protects against accidental data deletion. If you uploaded objects, delete only the intended demo data and **every object version/delete marker** in the AWS Console before retrying destroy. `aws s3 rm --recursive` alone does not remove all version history.

The optional manually created OIDC scanner role/policy are outside this Terraform root and need separate deletion if no longer used. Do not delete a shared GitHub OIDC provider used by other repositories.

No compute/NAT/RDS/EKS services are created. Empty networking/IAM configuration does not create a compute bill, but S3 requests/storage, optional services you add, GitHub Actions quotas and your wider AWS account usage remain relevant. Check the AWS billing console and clean up after the exercise. [S3 pricing](https://aws.amazon.com/s3/pricing/)

After destruction, an old baseline will report missing resources. That is expected. Preserve it privately if needed for your report; regenerate a new baseline only after a new deployment has been reviewed.

## 11. Useful daily commands

| Purpose | Command |
|---|---|
| Activate WSL environment | `source .venv/bin/activate` |
| Clean local proof | `python -m drift_detector demo --clean` |
| Local security findings | `python -m drift_detector demo` |
| Local demo UI | `python -m drift_detector serve --demo` |
| Real scan | `python -m drift_detector scan` |
| Real UI | `python -m drift_detector serve` |
| High/critical display | `python -m drift_detector scan --severity high` |
| IAM-only scan | `python -m drift_detector scan --resource iam_role` |
| JSON plus CI threshold | `python -m drift_detector scan --format json --output reports/scan.json --fail-on high` |
| Optional event context | `python -m drift_detector scan --cloudtrail` |
| Unit/SDK/UI tests | `python -m pytest -q` |

`--fail-on high` can return 0 even if lower-severity findings are present. Read report totals as well as the exit code. `--severity` is a display filter; it never changes the exit decision.

CloudTrail is optional and requires `cloudtrail:LookupEvents`. The default enrichment window is 24 hours and activity can be delayed or absent from resource-name lookup. Core detection works even when enrichment is unavailable.

## 12. Troubleshooting

| Symptom | Meaning and next action |
|---|---|
| `No module named drift_detector` | Activate the correct environment and reinstall from the folder containing `pyproject.toml`. |
| Flask import/dependency error | Run `python -m pip install -e ".[web]"`. |
| AWS `NoCredentialsError` | Choose the correct profile; sign in with SSO or refresh temporary credentials. |
| `ExpiredToken` | Refresh the AWS session and rerun the scan. |
| Account/region mismatch | The baseline and selected credentials/region disagree. Correct the selection; do not edit the baseline to conceal it. |
| `AccessDenied` / incomplete scan | Add the named resource's read permissions to the scanner identity. Exit 2 is not a security-clean result. |
| Baseline does not exist | Apply Terraform, then run `python -m drift_detector baseline`. |
| Baseline already exists | Keep it for drift detection. Use `--force` only after a deliberate reviewed baseline update. |
| Integrity check failed | Recover the known trusted baseline. A checksum can detect corruption but cannot establish who authored it. |
| Baseline verification shows drift immediately | Confirm workspace, Terraform apply completion and AWS propagation; inspect the exact configuration delta. |
| Duplicate SG rule error | The drift rule already exists. Scan and restore rather than repeatedly adding it. |
| Demo refuses an attached group | Do not bypass the check; use the project's unused group. |
| CloudTrail warning but findings present | Core detection succeeded. Check LookupEvents access, region and event latency separately. |
| Deleted resource finding | Verify intentional deletion versus accidental removal; plan with the original Terraform state. |
| BucketNotEmpty during destroy | Review and delete intended demo object versions/delete markers; retry destroy. |
| UI request rejected | Open the actual localhost URL and refresh before submitting; host/CSRF checks protect the local interface. |
| PowerShell JSON file cannot load | Avoid old PowerShell UTF-16 redirection. Use provided export commands, which write UTF-8. |

Configuration environment variables: `DRIFT_BASELINE_PATH`, `DRIFT_AWS_REGION`, `DRIFT_ENABLE_CLOUDTRAIL` and `DRIFT_LOG_LEVEL`; normal `AWS_PROFILE` and AWS credential resolution also apply. `.env.example` is a reference file, not automatically loaded.

## 13. GitHub upload and scheduled scanning

The ZIP is ready to put into your own repository. Run tests first, then inspect `git status` before committing. Never commit `.baseline`, real tfvars, state, `.env`, credentials or live reports. The checked-in fixtures use sanitized example identifiers.

From a newly extracted folder without Git history:

```bash
git init
git add .
git status --short
git commit -m "Build AWS cloud security drift detector"
```

Create an empty repository under your account and follow GitHub's supplied remote/push commands. Repository publishing and AWS deployment are separate manual steps.

Python/Terraform validation workflows need no AWS credentials. For actual scheduled scans, follow [docs/github-actions.md](docs/github-actions.md): a separate read-only OIDC role, exact repository/environment trust, protected baseline secret and explicit enable variable. There is no hidden state download or fake baseline generation in the workflow.

## Final acceptance checklist

- [ ] Offline clean demo returns 0 and no findings.
- [ ] Offline drift demo returns 1 and the expected findings.
- [ ] UI scan, clean scenario, filters and JSON download work.
- [ ] Ruff and pytest pass.
- [ ] Terraform fmt, validate and mock tests pass in your environment.
- [ ] STS confirms the intended AWS account.
- [ ] Terraform apply succeeds with only the small intended resources.
- [ ] Initial baseline verifies live state; first scan is clean.
- [ ] Controlled SSH drift produces CRITICAL `SG_PUBLIC_SSH`.
- [ ] Optional S3/IAM scenarios produce their expected findings.
- [ ] Terraform apply restores the configuration; the original baseline scans clean.
- [ ] Destroy succeeds; scheduled scans are disabled and optional scanner-role cleanup is reviewed.

For what was validated locally versus what still requires AWS, see [VALIDATION.md](VALIDATION.md).

# GitHub Actions, OIDC and baseline persistence

## Three separate workflows

| Workflow | AWS authentication | Behavior |
|---|---|---|
| Python CI | None | Ruff, pytest on Python 3.11/3.12/3.13, wheel build and installed-wheel clean demo |
| Terraform validation | None | Format, provider initialization, validate and mocked Terraform plans; never applies real infrastructure |
| Live security drift scan | Dedicated read-only OIDC role | Manual or scheduled scan against a protected, previously reviewed baseline; JSON artifact; severity/error gate |

This repository does not pretend a new GitHub runner has your local Terraform state. Real deployment/plan/apply remains local with the actual workspace and state. The scan workflow receives only the small trusted baseline and does not regenerate it from live AWS.

The scheduled workflow is disabled until **repository variable** `DRIFT_SCAN_ENABLED` is set to `true`. Its cron is `17 */6 * * *` in UTC, not Melbourne time. GitHub schedules are best effort and normally run from the default branch.

## 1. Complete the local AWS demo first

Deploy and generate a verified baseline using [SETUP_AND_TESTING.md](../SETUP_AND_TESTING.md). Keep infrastructure management under a provisioner identity. Export the separate scanner identity's exact read policy:

```bash
python scripts/export_config.py scanner-policy --output .baseline/scanner-policy.json
```

This policy is generated from Terraform resource identifiers. It includes bucket configuration reads, region-scoped DescribeSecurityGroups, reads for the demo role and default-version reads for AWS/account managed policies. No AWS write permissions are present. `sts:GetCallerIdentity` does not require adding an Allow to this identity policy. [AWS STS reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) CloudTrail lookup is included only when Terraform variable `enable_cloudtrail=true`; update the exported scanner policy if you later enable it.

The monitored demo role is a **different identity**. Do not attach the scanner policy to it or use it as the GitHub role.

## 2. Create the GitHub environment and branch restriction

In your GitHub repository:

1. Create environment **`drift-scan`** under Settings → Environments.
2. Restrict deployment branches to your protected default branch (for example `main`). Do not allow arbitrary feature branches to use this environment.
3. Protect changes to workflows and Terraform/baseline approval. Optional required reviewers improve control but also make scheduled runs wait for approval; choose that behavior deliberately.
4. Never grant AWS access to `pull_request_target` code from untrusted contributions. The live workflow has no PR trigger.

The role trust will use the exact environment subject. Because environment OIDC subjects do not embed the branch name, **the environment's branch restriction is essential**. [GitHub's AWS OIDC guidance](https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)

## 3. Create or reuse the account's GitHub OIDC provider

In AWS IAM → Identity providers:

- Provider type: OpenID Connect.
- Provider URL: `https://token.actions.githubusercontent.com`.
- Audience: `sts.amazonaws.com`.

Reuse an existing provider with those settings if the account already has one. The following helper targets commercial AWS, which is the documented deployment target; non-commercial partitions need corresponding ARN/audience review.

Generate an exact trust policy using **your** account ID and exact repository spelling. These example arguments are configuration placeholders, not real credentials:

```bash
python scripts/export_config.py oidc-trust \
  --account-id 123456789012 \
  --repository YOUR_GITHUB_NAME/cloud-security-drift-detector \
  --output .baseline/github-trust.json
```

PowerShell can run the same command on one line. The generated document permits only:

```text
Audience: sts.amazonaws.com
Subject: repo:YOUR_GITHUB_NAME/cloud-security-drift-detector:environment:drift-scan
Action: sts:AssumeRoleWithWebIdentity
```

Have your AWS administrator create a separate role, for example `github-drift-scanner`, with this trust policy and the exported `scanner-policy.json` as its inline permissions policy. Use the AWS Console JSON editor, or these explicit IAM commands using authorized administrator/provisioner credentials:

```bash
aws iam create-role --role-name github-drift-scanner --assume-role-policy-document file://.baseline/github-trust.json
aws iam put-role-policy --role-name github-drift-scanner --policy-name DriftScannerRead --policy-document file://.baseline/scanner-policy.json
```

These commands create **scanner identity configuration**, not monitored demo drift. They are not run by this repository automatically. For an existing role, review it and update its trust/permissions rather than attempting duplicate creation.

## 4. Persist the reviewed baseline securely

Open GitHub environment **drift-scan** → Environment secrets. Create:

| Name | Value |
|---|---|
| `DRIFT_BASELINE_JSON` | Full UTF-8 contents of `.baseline/security_baseline.json`, including `integrity_sha256` |

Paste the actual file contents, not a filename, sanitized example or escaped JSON string. The workflow writes those bytes to a private runner file and validates the schema/checksum before assuming the scanner role. It never prints the baseline secret directly.

This three-resource baseline is small enough for GitHub's 48 KB secret limit. Check the size if you extend scope. For larger deployments, use a separately protected, versioned baseline object and read-only retrieval design; that infrastructure is not implemented here. Do not silently substitute a freshly captured live snapshot. [GitHub secret limits](https://docs.github.com/en/actions/reference/security/secrets)

The checksum is not a signature. Repository/environment administrators who can replace the secret can change what is trusted. Protect review rights accordingly.

## 5. Set variables and enable scanning

Set these **repository Actions variables** under Settings → Secrets and variables → Actions → Variables:

| Name | Example / purpose |
|---|---|
| `DRIFT_SCANNER_ROLE_ARN` | Actual ARN of the separate OIDC read role |
| `DRIFT_AWS_REGION` | `ap-southeast-2`, matching the deployed baseline |
| `DRIFT_FAIL_ON` | `HIGH` (or INFO, LOW, MEDIUM, CRITICAL) |
| `DRIFT_SCAN_ENABLED` | `true` when setup is complete; `false` to pause |

Keep `DRIFT_SCAN_ENABLED` at repository level: it is evaluated before the job enters its environment. The baseline stays an **environment secret**, not a repository file.

Under Actions → Live security drift scan, select **Run workflow** from the allowed branch. Verify:

1. Reviewed baseline is accepted.
2. OIDC short-lived AWS credentials are obtained for the scanner role.
3. The scanner checks the expected account and region.
4. A report artifact is saved, including on security findings/incomplete scan.
5. The job passes below the selected threshold, fails with exit 1 for threshold findings, or fails with exit 2 for incomplete/error.

Action implementations are pinned to immutable commit SHAs. No long-lived AWS key is stored in workflow files. Monthly Dependabot updates let you review changes to pinned actions/providers/dependencies.

## Reports and privacy

The workflow suppresses JSON stdout and uploads `reports/drift-report.json` with seven-day retention. The report can contain account IDs, bucket names, ARNs and optional actor/source-IP context. Review who can access Actions artifacts, especially for a public portfolio repository. Use a dedicated sandbox and sanitized screenshots; do not publish production account metadata casually.

Security findings do not stop report upload: the workflow captures the detector exit code, archives available output, then applies that code as a final gate. A pre-scan setup/authentication failure stays failed even if no report could be created. The local baseline file is removed at job completion; the protected environment secret remains until you update/delete it.

## Updating and cleanup

For an **approved** infrastructure configuration change, run local plan/apply, `baseline --force`, verify clean, then replace `DRIFT_BASELINE_JSON` with the newly reviewed file. Update scanner policy if resource identifiers or permissions change. Never rebaseline solely to dismiss a finding.

Before Terraform destroy, set `DRIFT_SCAN_ENABLED=false`. The manually created scanner IAM role/inline policy are outside the root module; remove them separately when no longer needed. Do not delete a shared OIDC provider used by other repositories. Delete the protected baseline secret once retention/review needs are satisfied.

## Optional local scheduling

You can use cron instead of GitHub. In a shell script, change into the project root, activate the venv or call its interpreter by absolute path, select the AWS profile/region, and run `scan --format json --output reports/latest.json --fail-on high`. Use a role or refreshable credentials; interactive SSO expiration will cause exit 2 and must be handled operationally. Do not interpret an expired login as clean posture.

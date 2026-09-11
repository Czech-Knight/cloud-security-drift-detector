# Threat model and scope

## Assets and threats

The monitored assets are intended IAM permissions/trust, S3 bucket access/recovery controls and SG network permissions. Threats include accidental console changes, Terraform bypass, unexpectedly broad access, privilege-escalation-capable permissions, stolen highly privileged credentials, malicious baseline edits and misleading clean results caused by missing read permissions.

| Boundary | Trusted input | Main risk | Current control |
|---|---|---|---|
| Terraform → baseline | Reviewed configuration and correct applied workspace | Drift or malicious edits accepted as intended | Authored output contract, live verification, explicit replacement flag |
| Baseline → scanner | Protected local JSON | Account mix-up, corruption, false expected state | Schema/identity checks, checksum for corruption, private file creation |
| Credentials → AWS | Standard AWS identity chain | Wrong account/region, overprivileged scanner | STS/region checks, separate generated read policy |
| AWS → collectors | SDK responses within granted scope | AccessDenied treated as safe, partial policy enumeration | Pagination, explicit absence codes, errors and exit 2 |
| GitHub → AWS | Exact repository environment OIDC subject | Untrusted code assumes role or edits baseline | Environment/branch restrictions, exact aud/sub, read-only role, pinned actions |
| Browser → local app | Loopback user session | Cross-site scan requests or misleading cached output | Host allowlist, CSRF token, strict cookies, no-store, no debugger |
| Findings → reviewer | Deterministic rule interpretation | Configuration mistaken for exploitation | Qualifying reachability/effective-access explanations and explicit limitations |

## What this is and is not

This project detects selected configuration drift. It is not a GuardDuty replacement, general CSPM platform, SIEM, malware detector, vulnerability scanner, runtime intrusion detector or full AWS Config replacement.

A clean scan means the selected monitored properties were completely read and no implemented rule found a qualifying change. It does not prove an account is safe, that no compromise happened, or that unmonitored resources match policy. A weak setting already intentionally approved in a baseline is generally outside drift detection; baseline review remains essential.

The Terraform defaults are secure and narrowly scoped, but this project is not a formal deployment hardening standard. S3 data-plane permissions, object ACLs, access points, account-level public access controls, SSE-C blocking, IAM permissions boundaries/SCPs/session policies, VPC routing and SG references' transitive contents are outside this first release's evaluator.

## Baseline integrity and trust

The file checksum detects accidental edits only. An attacker able to replace both settings and checksum can defeat it. Restrict write access, protect repository branches/workflows, and keep reviewed baselines out of public source. Signed baselines with a separately managed signing key are future work. The baseline may contain resource/account metadata even though it contains no AWS secret keys.

The scanner is read-only. Baseline writes are local, explicit operations. Restoration remains a separately reviewed Terraform apply. The explicit unsafe demo script uses deployer permissions and never runs during tests, normal scan or UI scan. Its tag/ENI preflight checks reduce accidental targeting but cannot atomically prevent a concurrent workload attachment.

## API and rule limits

IAM evaluation examines newly added/modified Allow statements and trust structure. Deny statements, conditions and external authorization layers may constrain real access; the tool reports potential risk rather than claiming a working escalation path. `Action:*` plus broad resource scope is serious, but still subject to effective-account restrictions. The unscopable-read exception list is intentionally short and not the entire IAM service authorization reference.

The normalizer removes ordering and representation differences. It does not solve policy equivalence or compare arbitrary overlapping CIDR sets as a full network-reachability engine. Removing expected network permissions is visible as configuration drift without necessarily being an exposure finding. Public rules remain findings even when the demo lacks routes or workloads; their explanations distinguish the control from actual reachability.

S3 missing configuration does not prove plaintext storage: modern new uploads have automatic SSE-S3. Versioning suspension affects new version creation and recovery, not automatic deletion of old versions. CloudTrail events are contextual, may arrive late and may have poor resource-name indexing; absence is not exoneration and presence is not causation.

## Operational handling

Use a separate provisioner/scanner role. Revoke/refresh compromised credentials outside this tool. Review reports before sharing because they can include account IDs, ARNs, actor names and source IPs. Keep the UI local; it is not designed as a public authenticated service.

Restore drift using the original Terraform state and workspace; do not replace expected state to silence alerts. Review a non-empty versioned bucket before destroying data. If an IAM role was actually abused, removing a policy is only one part of incident response; investigate sessions, actions and any persistence separately.

"""Rule metadata is the single source for findings and the generated rule reference."""

from drift_detector.models import Finding, Resource

RESTORE = "Review terraform -chdir=terraform plan, then run terraform -chdir=terraform apply. Rescan after AWS propagation."
# rule_id: severity, title, explanation, specific remediation
CATALOG = {
    "RESOURCE_MISSING": (
        "HIGH",
        "Monitored resource is missing",
        "The API positively reported the resource absent. This can remove security controls or interrupt workloads; account and region have already been checked.",
        "Confirm whether deletion was intentional and restore the resource if required.",
    ),
    "S3_PUBLIC_ACCESS_BLOCK_DISABLED": (
        "HIGH",
        "S3 public access protection was weakened",
        "One or more bucket-level public access guardrails changed from enabled to disabled. This increases the chance that a later policy or ACL change exposes data. It does not alone prove public reachability; account-level controls may still block access.",
        "Re-enable the expected Block Public Access settings and review the bucket policy and ACL.",
    ),
    "S3_PUBLIC_POLICY": (
        "CRITICAL",
        "S3 reports a public bucket policy",
        "S3 classifies the bucket policy as public. The grant may allow access outside intended principals; Block Public Access and other controls can still prevent effective access.",
        "Remove unintended public Allow statements and restore the Terraform bucket policy.",
    ),
    "S3_PUBLIC_ACL": (
        "HIGH",
        "S3 ACL grants access to a broad group",
        "The ACL now grants AllUsers or AuthenticatedUsers access. AuthenticatedUsers is not limited to your AWS account. ACL enforcement still depends on object ownership and public access controls.",
        "Remove the broad ACL grants and restore BucketOwnerEnforced ownership.",
    ),
    "S3_ACL_CHANGED": (
        "MEDIUM",
        "S3 ACL grants changed",
        "Bucket ACL grantees or permissions differ from the baseline. An unexpected canonical-user grant can expose data to another account when ACLs are effective.",
        "Review the exact ACL grant differences and remove unapproved grants.",
    ),
    "S3_OWNERSHIP_CHANGED": (
        "HIGH",
        "S3 ownership controls changed",
        "Moving away from BucketOwnerEnforced can re-enable ACL-based access and weaken the intended ownership model.",
        "Restore BucketOwnerEnforced ownership after reviewing ACLs.",
    ),
    "S3_ENCRYPTION_DISABLED": (
        "HIGH",
        "Expected S3 encryption configuration is missing",
        "The expected encryption configuration could not be found. Modern S3 still automatically encrypts new uploads with SSE-S3; this finding does not mean objects are stored in plaintext. A required KMS policy may have been lost.",
        "Restore the expected default encryption configuration and verify any KMS key requirement.",
    ),
    "S3_ENCRYPTION_WEAKENED": (
        "HIGH",
        "S3 encryption policy changed or weakened",
        "The default encryption algorithm or KMS key differs. A KMS-to-SSE-S3 change removes the expected customer key controls, although encryption at rest remains. Key changes need review even when the algorithm is unchanged.",
        "Restore the intended algorithm and KMS key. Review affected object uploads separately.",
    ),
    "S3_ENCRYPTION_CONFIGURATION_CHANGED": (
        "LOW",
        "S3 encryption configuration changed",
        "Encryption settings differ from the baseline. A Bucket Key setting change affects KMS request behavior and should be reviewed, but does not itself disable encryption.",
        "Review the encryption setting difference and restore the approved configuration.",
    ),
    "S3_VERSIONING_DISABLED": (
        "MEDIUM",
        "S3 versioning is no longer enabled",
        "New writes no longer create the expected recoverable object versions. This weakens recovery from overwrites and accidental deletion; existing versions are not automatically erased.",
        "Enable versioning again and review writes since the change.",
    ),
    "S3_HTTPS_ONLY_POLICY_REMOVED": (
        "HIGH",
        "S3 HTTPS enforcement was removed or narrowed",
        "The baseline deny for insecure transport is no longer present across the bucket and its objects. Requests over unencrypted transport may be accepted if another policy allows them.",
        "Restore the Deny on s3:* for aws:SecureTransport=false covering both the bucket ARN and its objects.",
    ),
    "S3_POLICY_CHANGED": (
        "MEDIUM",
        "S3 bucket policy changed",
        "The normalized bucket policy differs. New principals, actions, resources or conditions may alter access even when S3 does not label the policy public.",
        "Review the expected and actual policy statements and restore approved access.",
    ),
    "SG_PUBLIC_SSH": (
        "CRITICAL",
        "Security group permits public SSH",
        "The new rule permits TCP/22 from the entire internet, increasing exposure to password attacks, stolen credentials and exploitable SSH services. Actual reachability also needs an attached workload, routing and a listening service; this demo SG is unattached.",
        "Remove the public SSH rule or restore the trusted administrator CIDR.",
    ),
    "SG_PUBLIC_RDP": (
        "CRITICAL",
        "Security group permits public RDP",
        "The new rule permits TCP/3389 from the internet, exposing any reachable RDP service to credential attacks and vulnerabilities. This is a permissive network control, not proof a host is reachable.",
        "Remove public RDP ingress; require a private access path or approved CIDR.",
    ),
    "SG_PUBLIC_DATABASE_PORT": (
        "CRITICAL",
        "Security group permits a public database port",
        "The new TCP/UDP range includes a database port (1433, 3306, 5432, 6379 or 27017) from the internet. Reachable services face authentication attacks, data access and service-specific vulnerabilities.",
        "Restrict database ingress to the application security group or approved private CIDR.",
    ),
    "SG_ALL_PORTS_PUBLIC": (
        "CRITICAL",
        "Security group permits all ports publicly",
        "The new rule permits all protocols, or the full TCP/UDP port range, from the internet. Any reachable attached service may become exposed, including services never intended to be public.",
        "Remove the broad rule and restore only the required ports and sources.",
    ),
    "SG_IPV6_PUBLIC_EXPOSURE": (
        "HIGH",
        "Unexpected public IPv6 ingress",
        "The new ::/0 rule permits traffic from every IPv6 address. IPv4 restrictions do not constrain this independent IPv6 path.",
        "Remove the unexpected IPv6 rule or restrict its source and ports.",
    ),
    "SG_UNEXPECTED_INGRESS": (
        "MEDIUM",
        "Unexpected security group ingress",
        "An ingress permission was added outside the baseline. Review its source and service; even private ranges can expand lateral movement opportunities.",
        "Remove the unapproved ingress rule or deliberately update reviewed Terraform configuration.",
    ),
    "SG_CIDR_BROADENED": (
        "HIGH",
        "An ingress CIDR was broadened",
        "For the same protocol and port range, the source network now includes more addresses than the trusted baseline. More hosts can attempt connections to attached services.",
        "Restore the narrower trusted CIDR.",
    ),
    "SG_UNEXPECTED_EGRESS": (
        "MEDIUM",
        "Unexpected security group egress",
        "An outbound permission was added. It may enable new destinations for data transfer or command-and-control traffic from an attached workload.",
        "Remove the new egress permission or approve only required destinations and ports.",
    ),
    "IAM_ADMIN_POLICY_ATTACHED": (
        "CRITICAL",
        "AdministratorAccess attached to demo role",
        "The role gained AWS AdministratorAccess. This permits all actions and resources within effective account controls; SCPs, boundaries and explicit denies may still limit access.",
        "Detach AdministratorAccess from this demo role and restore the approved attachments.",
    ),
    "IAM_BROAD_MANAGED_POLICY": (
        "HIGH",
        "Broad AWS managed policy attached",
        "A newly attached AWS managed FullAccess/PowerUser policy can greatly expand the role's permissions. Review the actual policy document and effective account controls.",
        "Detach the unapproved broad managed policy and use a resource-scoped policy.",
    ),
    "IAM_UNEXPECTED_POLICY_ATTACHMENT": (
        "MEDIUM",
        "Unexpected managed policy attachment",
        "The role has an attachment absent from the trusted baseline. The collected default policy version shows the additional permissions requiring review.",
        "Detach unapproved policies or deliberately approve them in Terraform.",
    ),
    "IAM_BASELINE_POLICY_REMOVED": (
        "MEDIUM",
        "A baseline IAM policy was removed",
        "An expected policy is missing. This can break intended access or remove an explicit deny guardrail; removal does not always increase privileges.",
        "Restore the expected policy attachment or inline policy.",
    ),
    "IAM_INLINE_POLICY_ADDED": (
        "MEDIUM",
        "Unexpected inline IAM policy",
        "A new inline policy bypasses the reviewed policy set and can introduce permissions that are not visible in the attachment list.",
        "Remove the unapproved inline policy and restore the Terraform-managed set.",
    ),
    "IAM_POLICY_CHANGED": (
        "MEDIUM",
        "IAM policy permissions changed",
        "A normalized inline policy or managed policy default version changed. Statement order alone does not trigger this finding.",
        "Review the exact document diff. Restore the approved policy version or inline document.",
    ),
    "IAM_WILDCARD_ACTION": (
        "HIGH",
        "IAM action scope broadened with a wildcard",
        "An added Allow statement contains a wildcard action. Action:* includes every action within its resource and condition scope; service wildcards can also include future service operations.",
        "Replace wildcard actions with the minimum explicit actions needed.",
    ),
    "IAM_WILDCARD_RESOURCE": (
        "HIGH",
        "IAM Allow statement uses broad resources",
        "An added Allow statement uses wildcard resource scope for actions not all recognized as inherently unscopable reads by this tool. Conditions and IAM resource-level support must be reviewed before deciding effective exposure.",
        "Use specific ARNs where supported and restrictive conditions where resource-level permissions are unavailable.",
    ),
    "IAM_NEGATED_ALLOW": (
        "HIGH",
        "IAM Allow uses a negated scope",
        "An added Allow uses NotAction or NotResource, potentially granting everything outside a small exclusion. A short policy can therefore create broad permissions.",
        "Replace broad negated Allows with explicit approved actions and resources.",
    ),
    "IAM_PRIVILEGE_ESCALATION_RISK": (
        "HIGH",
        "Potential IAM privilege escalation permissions",
        "New permissions include policy/trust mutation, or role passing with workload creation, or broad AssumeRole. These can support escalation when combined with a usable target role or other permissions. This heuristic does not prove an exploitable path.",
        "Remove unnecessary IAM mutation/role delegation permissions; constrain role ARNs, iam:PassedToService and trust conditions where applicable.",
    ),
    "IAM_TRUST_POLICY_BROADENED": (
        "HIGH",
        "IAM role trust broadened",
        "The trust policy adds principals or uses a wildcard principal. Additional callers may be able to assume the role if identity permissions and trust conditions allow them. Inspect the complete trust statement.",
        "Restore the intended trusted principals and conditions; remove wildcard trust.",
    ),
    "IAM_TRUST_POLICY_CHANGED": (
        "MEDIUM",
        "IAM role trust conditions or actions changed",
        "The normalized trust policy differs even though no new principal was identified. Removed conditions or altered federation/AssumeRole actions can materially change who can obtain sessions.",
        "Review and restore the approved trust actions and conditions.",
    ),
}


def finding(
    rule_id: str, resource: Resource, expected, actual, severity: str | None = None
) -> Finding:
    level, title, explanation, remediation = CATALOG[rule_id]
    return Finding(
        rule_id,
        resource.type,
        resource.id,
        resource.arn,
        title,
        severity or level,
        expected,
        actual,
        explanation,
        f"{remediation} {RESTORE}",
    )

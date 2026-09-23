# Enterprise deployment: cross-account drift response

This is an **opt-in reference deployment**, not an automatic change to the original single-account demo. Keep the provisioner, detector and event transport roles separate. The original read-only CLI and six-hour GitHub Actions scan continue to work unchanged.

## Architecture and guarantees

1. Keep one reviewed, checksum-validated Terraform-derived baseline per AWS **account + region**. Never use a live snapshot to overwrite a baseline after unexpected drift.
2. A central detector identity may call STS AssumeRole into an explicitly permitted read-only scanner role in each monitored account. Target account identity is checked against both inventory and the saved baseline before any resource reads.
3. Deploy the central EventBridge bus and encrypted SQS queue with a DLQ from deploy/event-hub. Each source account/region forwards matching CloudTrail write events via deploy/event-forwarder. The queue worker scans **all configured regions of the event's account**, avoiding brittle resource-name parsing and IAM/global-service event routing assumptions.
4. A complete scan acknowledges its event even if it finds security drift. An incomplete scan, unknown account or malformed event is not acknowledged and will be retried/redriven to the DLQ. Keep a recurring full fleet scan as a backstop: event delivery is best effort, not guaranteed instantaneous or complete.
5. The event worker **never applies changes**. An authorized operator prepares a saved Terraform plan against the original workspace, obtains external change approval, verifies the exact plan hash, applies that exact plan and checks live AWS against the unchanged baseline again.

CloudTrail/EventBridge latency, STS throttling, regional coverage, credentials expiry and cost vary. This is **near-real-time event-triggered rescan**, not a claim of millisecond response or complete AWS resource coverage. Rules still cover only the S3/SG/IAM settings defined in the baseline.

## 1. Prepare reviewed baselines and least-privilege roles

In each target account/region, deploy the existing demo or adapt its explicitly authored Terraform security_baseline output to your approved environment, verify the actual resources and run:

    python -m drift_detector baseline --terraform-dir terraform --baseline .baseline/account-ACCOUNT-REGION.json

Retain baselines in an access-controlled store. The integrity_sha256 detects accidental corruption, **not malicious baseline substitution**; require code review and restrict baseline writers. Inventory paths resolve relative to the inventory JSON file, not your shell's working directory. Never commit production baselines, access tokens, account identifiers or report artifacts.

Create a dedicated read-only role in **each monitored account**, using the existing scanner_policy output as a starting point for that account's monitored resources. Permit sts:AssumeRole in its trust policy **only** for your central worker role (and require an ExternalId for cross-organization trust when appropriate). Give the central worker role sts:AssumeRole on only the enumerated target role ARNs; do not give that central identity broad target-resource read/write permissions or Terraform provisioner permissions. For each account in your central inventory include the exact role ARN, account ID, region and reviewed baseline path:

    cp examples/fleet-inventory.example.json .baseline/fleet.json
    # Edit all placeholders to your authorized account IDs, regions, role ARNs and paths.
    python -m drift_detector fleet --inventory .baseline/fleet.json --fail-on HIGH --output reports/fleet.json

If you move inventory into .baseline, adjust the sample relative baseline paths: the supplied example assumes the inventory remains in examples/. For a production inventory, prefer absolute paths inside your protected baseline store. The default central credential chain may use SSO or a short-lived role; --profile is optional. A target AssumeRole error or any incomplete resource read produces exit 2 for the fleet, not a false clean result. Exit 1 means a finding meets --fail-on; exit 0 means scans completed below that threshold.

Run this full fleet command periodically even when event monitoring is enabled. A missing event is not evidence of compliance.

## 2. Provision event transport (optional, actual AWS resources)

In the **central AWS account**, using an authorized deployment identity:

    terraform -chdir=deploy/event-hub init
    terraform -chdir=deploy/event-hub apply -var='aws_region=ap-southeast-2' -var='allowed_account_ids=["111111111111","222222222222"]'
    terraform -chdir=deploy/event-hub output

The hub creates a custom event bus, account-scoped PutEvents permissions, an encrypted SQS queue, an SQS DLQ, a CloudTrail-management-write event rule and an SQS policy restricted to that rule. Record event_bus_arn and queue_url. Change example accounts to your actual authorized values.

In **each monitored source account and each region that must be covered**, deploy the separate forwarder with that region and central event bus ARN (use its own state/credentials, never the target scanner role):

    terraform -chdir=deploy/event-forwarder init
    terraform -chdir=deploy/event-forwarder apply -var='aws_region=ap-southeast-2' -var='central_event_bus_arn=arn:aws:events:ap-southeast-2:111111111111:event-bus/drift-security-events'

The forwarder sends matching EventBridge CloudTrail management-write events to the central bus; deploy in us-east-1 as appropriate for IAM global-service events and in each applicable region for regional services. The central bus permissions and source role must authorize the forwarding. Some CloudTrail events are delayed, missing or have different regions/fields; verify rules with controlled, authorized security changes. Only configured accounts are scanned. Restrict central worker SQS rights to ReceiveMessage/DeleteMessage on the hub queue, and set DLQ monitoring/alerting. Do not allow untrusted principals to SendMessage to the queue or PutEvents on the bus.

Run a worker under a central short-lived role, on a persistent supervised host/container with secure logs:

    python -m drift_detector events --inventory .baseline/fleet.json --queue-url https://sqs.ap-southeast-2.amazonaws.com/111111111111/drift-security-events --queue-region ap-southeast-2

For a one-batch smoke test use --once --poll-seconds 0. Each trigger prints a JSON fleet report tagged cloudtrail-event; ship this output to your protected incident/alert platform. An unhandled/incomplete event remains in SQS for retry and then moves to the DLQ (after the configured receive-count threshold). The worker uses a 900-second visibility timeout: size your fleet batches/processing time accordingly and make downstream alerts idempotent by event ID. Set a bounded retry/redrive policy, monitor oldest message age and DLQ depth, and use an independent periodic scan to cover lost events.

## 3. Review and remediate a detected change

**Nothing in fleet scan or the SQS worker calls Terraform apply.** Use the provisioner identity and original state/workspace, not the central scanner identity. The approval must come from your organization's **external** change system or protected CI environment, with an independently reviewed plan. The CLI records an approver/ticket string but does not authenticate the approver or itself enforce two-person authorization.

    python -m drift_detector remediate plan --baseline .baseline/security_baseline.json --terraform-dir terraform --plan-path .remediation/reconcile.tfplan
    terraform show .remediation/reconcile.tfplan

Review the entire plan, including any unrelated updates/destroys. The command refuses to overwrite an existing saved plan and prints its SHA-256 and account/region/workspace. Run terraform show on the exact saved plan before approval; terraform show does not need a working-directory switch when the plan path is given from the repository root. Obtain external approval for that **exact** plan checksum, then explicitly execute:

    python -m drift_detector remediate apply --baseline .baseline/security_baseline.json --terraform-dir terraform --plan-path .remediation/reconcile.tfplan --approved-plan-sha256 APPROVED_64_HEX_DIGEST --approval-ticket CHG-1234 --approved-by REVIEWER_ID --confirm-apply

Apply rejects a changed plan, missing approval metadata, wrong AWS account or wrong Terraform workspace. It applies the exact saved plan, then reads the live environment again. Remaining drift/incomplete reads fail verification; do not close the incident or regenerate a baseline to conceal them. Terraform plan files can contain secrets, are kept local at owner-only mode and must not be uploaded to public CI artifacts. An independent reviewer, protected plan store and approved workflow are required before calling this production change management. Terraform plans can grow stale; if Terraform refuses the saved plan, regenerate and reapprove a new one.

## Scope and outstanding production requirements

This reference implementation does not discover all AWS Organization accounts automatically, provision cross-account read roles, cover all services, prove network reachability, integrate a ticketing/IdP approval API, cryptographically validate reviewer signatures, deduplicate event delivery across worker restarts or implement a managed worker deployment. Provision and secure those pieces before production adoption. For the existing three-resource demo, the original periodic single-account scan remains an independent backstop.

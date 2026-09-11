# Architecture and data contracts

## Expected versus actual

Terraform's `security_baseline` output is the stable interface between infrastructure and Python. It contains identifiers and explicitly authored security settings. Expected policy documents and SG rules use Terraform locals, not refreshed security-sensitive resource attributes. Refreshing state therefore does not silently rewrite intended permission sets.

`baseline` reads full `terraform output -json`, validates the contract with Pydantic, normalizes it, verifies live AWS, and writes a private local file. It refuses any configuration delta or incomplete resource read during generation. `--force` is required to replace an existing baseline. `--skip-live-verification` is an explicit offline-export escape hatch, not part of the normal deployment flow.

The application never parses raw `.tfstate`. Terraform configuration, workspace/state provenance and the stored baseline remain the operator's trust responsibilities.

## Pipeline and code locations

| Layer | Location | Responsibility |
|---|---|---|
| Auth | `aws/session.py` | Standard boto3 credentials, STS account check, region check, bounded retries/timeouts |
| Collectors | `aws/s3.py`, `aws/ec2.py`, `aws/iam.py` | Complete security state for each resource, pagination, exact absence/error handling |
| Models | `models.py` | Strict baseline/resource/state schemas and report/finding dataclasses |
| Normalize | `baseline/normalizers.py` | Policy ordering, action case, singleton/list equivalence, atomic network sources, metadata removal |
| Compare | `engine/comparator.py` | Separate property deltas from security rule evaluation |
| Classify | `rules/*.py` | Deterministic severity and explanations; no external inference service |
| Orchestrate | `engine/scanner.py` | Continue across independent resource failures, report incomplete coverage |
| Present | `cli.py`, `reporting.py`, `web/app.py` | CLI, JSON and loopback-only Flask views of the same report |
| Enrich | `aws/cloudtrail.py` | Optional recent related events; never current-state truth |

## Baseline schema v1

Top-level keys are `schema_version`, `created_at`, `aws_account_id`, `aws_region`, `terraform_workspace`, `source`, `cloudtrail_enabled`, `resources` and `integrity_sha256` in the saved file. The Terraform output supplies the configuration fields; the builder adds creation time/source, and the writer adds the checksum.

Each resource has `type` (`s3`, `security_group` or `iam_role`), `id`, `arn` and `expected`. Duplicate resource identities, unknown fields, incorrect account/region ARN bindings and malformed property types fail validation. An empty resource selection does not count as a successful scan.

- **S3 expected:** four public access block booleans, normalized bucket policy, AWS public-policy classification, ACL grants, ownership mode, default encryption settings, versioning status.
- **SG expected:** ingress/egress arrays of protocol, ports, source family and source. Multi-source AWS permissions are split into atomic rules. Descriptions are not security semantics. Group references retain account/group identity; prefix lists retain IDs, not expanded entries.
- **IAM expected:** normalized trust policy, inline name→document map, attached ARN→default-version-document map. Version numbers alone do not count as drift when the normalized permissions are unchanged.

Complete sanitized input examples are in `examples/terraform-output.json` and the packaged `fixtures` directory. `examples/security-baseline.json` is a saved schema-v1 example with integrity checksum. These are demonstrative identifiers, not evidence from a real AWS account.

## JSON report schema v1

A completed or partial scan includes account, region, `mode` (`live` or `offline-demo`), ISO timestamp, resource totals, findings, configuration `changes`, `errors`, `warnings` and `summary`.

Every finding includes `rule_id`, `resource_type`, `resource_id`, `resource_arn`, `title`, `severity`, `expected`, `actual`, `explanation`, `remediation`, `cloudtrail_events`.

`summary.status` is `incomplete` when any selected resource could not be read, `drift` when findings exist, otherwise `clean`. Configuration-only differences can coexist with `clean` security status. The UI displays both counters. `summary.findings` counts all findings in the selected resource scope; a presentation filter adds `summary.displayed_findings` while retaining the original totals.

A command-level error (such as no valid baseline) returns a smaller JSON envelope with schema version, error status, empty findings and an actionable `errors` list. It has no fabricated scan account, timestamp or resource totals. Consumers should check status/errors before expecting scan-only fields.

Default exit codes: 0 for a complete scan below the threshold, 1 for a threshold-crossing finding, 2 for any execution/configuration or coverage failure. `--fail-on` does not suppress findings in the report. Display filters do not alter the gate.

## Error and consistency semantics

A resource is missing only when AWS positively returns a corresponding absence response. S3 configuration absence is distinct from resource absence. AccessDenied, expired credentials, throttle exhaustion, malformed required API data and transient failures become errors. A role's failed managed-policy read invalidates collection of that whole role; partial policy sets never masquerade as complete state.

The scan reads services sequentially with standard SDK retry/backoff and short connect/read timeouts. It is not an atomic snapshot. A concurrent change can produce transient differences; rescan after propagation and investigate persistent findings. Each run refreshes managed policy documents; there is no stale global policy cache.

CloudTrail is independent and optional. Event lookups are capped to limit work, may be incomplete, and never turn a successful core scan into an error. Account/region identity checks happen before resource collection. No secret values or full CloudTrail request/response documents are emitted.

## Extension approach

For a new rule in an existing resource family, add metadata to `rules/catalog.py`, add the detection predicate in that family's `evaluate` function, and add a test for the triggering change plus a safe/ordering counterexample. Update `docs/security-rules.md` using the generator. For a new resource family, add a strict model, normalizer, collector, Terraform output and comparator registration. Avoid runtime plugin loading.

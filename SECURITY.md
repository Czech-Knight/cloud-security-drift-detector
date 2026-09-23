# Security policy

## Reporting a vulnerability

Please use the **Report a vulnerability** option under this repository's Security tab if private vulnerability reporting is enabled. Do **not** include exploit details, credentials, production resource identifiers or sensitive reports in public issues. If the option is unavailable, contact the maintainer privately before sending technical details.

## Scope

The Terraform directory contains an example infrastructure baseline. Running a scanner does not authorize deployment, cloud account access, or modification of resources. The scheduled live-drift workflow is separately controlled by a protected environment and a read-only AWS role.

## Maintainer response

Reports are triaged and remediated according to impact and reproducibility. The default branch is the supported development line; older releases may not receive security fixes.

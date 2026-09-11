#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
terraform -chdir=terraform plan
# Keep Terraform's approval prompt; the user reviews actual changes.
terraform -chdir=terraform apply
python -m drift_detector scan

#!/usr/bin/env python3
"""Write UTF-8 JSON configuration without platform-specific shell redirection."""

import argparse
import json
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("scanner-policy", "oidc-trust"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--account-id")
    parser.add_argument("--repository", help="Exact OWNER/REPOSITORY")
    parser.add_argument("--terraform-dir", default="terraform")
    args = parser.parse_args()
    if args.kind == "scanner-policy":
        try:
            response = subprocess.run(
                ["terraform", f"-chdir={args.terraform_dir}", "output", "-json", "scanner_policy"],
                capture_output=True,
                check=True,
                text=True,
                timeout=60,
            )
            data = json.loads(response.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            parser.error(
                "Run terraform apply first, then export the scanner policy from the same workspace."
            )
    else:
        if not re.fullmatch(r"\d{12}", args.account_id or "") or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository or ""
        ):
            parser.error("Use your 12-digit --account-id and exact --repository OWNER/REPO.")
        data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": f"arn:aws:iam::{args.account_id}:oidc-provider/token.actions.githubusercontent.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:sub": f"repo:{args.repository}:environment:drift-scan",
                        }
                    },
                }
            ],
        }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.kind}: {path}")


if __name__ == "__main__":
    main()

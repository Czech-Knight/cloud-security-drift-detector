"""Expected values come exclusively from the explicit Terraform output contract."""

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from drift_detector.models import Baseline, DetectorError


def build_baseline(terraform_dir: str = "terraform", output_file: str | None = None) -> Baseline:
    try:
        if output_file:
            raw = Path(output_file).read_text(encoding="utf-8")
        else:
            process = subprocess.run(
                ["terraform", f"-chdir={terraform_dir}", "output", "-json"],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            raw = process.stdout
        outputs = json.loads(raw)
        contract = outputs["security_baseline"]["value"]
        return Baseline.model_validate(
            {**contract, "created_at": datetime.now(UTC).isoformat(), "source": "terraform-output"}
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise DetectorError(
            "Cannot read Terraform security_baseline output. Run terraform init/apply in the correct workspace first."
        ) from exc

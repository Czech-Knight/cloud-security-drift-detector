"""The versioned contract shared by Terraform, collectors, rules and reports."""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SEVERITIES = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ResourceType = Literal["s3", "security_group", "iam_role"]


class DetectorError(Exception):
    """Expected, actionable configuration or execution failure."""


class MissingResource(Exception):
    """A resource was positively identified as absent, not inaccessible."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PublicAccessBlock(StrictModel):
    BlockPublicAcls: bool
    IgnorePublicAcls: bool
    BlockPublicPolicy: bool
    RestrictPublicBuckets: bool


class EncryptionState(StrictModel):
    algorithm: Literal["AES256", "aws:kms", "aws:kms:dsse"]
    kms_key_id: str | None = None
    bucket_key_enabled: bool = False


class S3State(StrictModel):
    public_access_block: PublicAccessBlock
    policy: dict[str, Any] | None
    policy_public: bool
    acl: list[dict[str, str]]
    ownership: str | None
    encryption: EncryptionState | None
    versioning: Literal["Enabled", "Suspended", "Disabled"]


class NetworkRule(StrictModel):
    protocol: str
    from_port: int | None
    to_port: int | None
    source_type: Literal["ipv4", "ipv6", "security_group", "prefix_list"]
    source: str


class SGState(StrictModel):
    ingress: list[NetworkRule]
    egress: list[NetworkRule]


class IAMState(StrictModel):
    trust_policy: dict[str, Any]
    inline_policies: dict[str, dict[str, Any]]
    attached_policies: dict[str, dict[str, Any]]


class Resource(StrictModel):
    type: ResourceType
    id: str = Field(min_length=1)
    arn: str = Field(pattern=r"^arn:")
    expected: dict[str, Any]

    @model_validator(mode="after")
    def validate_state(self):
        from drift_detector.baseline.normalizers import normalize_state

        self.expected = normalize_state(self.type, self.expected)
        return self


class Baseline(StrictModel):
    schema_version: Literal[1] = 1
    created_at: str
    aws_account_id: str = Field(pattern=r"^\d{12}$")
    aws_region: str = Field(pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
    terraform_workspace: str = Field(min_length=1)
    source: Literal["terraform-output"] = "terraform-output"
    cloudtrail_enabled: bool = False
    resources: list[Resource] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_resources(self):
        keys = [(r.type, r.id) for r in self.resources]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate resource identifiers in baseline")
        for resource in self.resources:
            parts = resource.arn.split(":", 5)
            if len(parts) != 6:
                raise ValueError("Invalid resource ARN")
            _, _, service, region, account, suffix = parts
            if resource.type == "s3":
                valid = service == "s3" and suffix == resource.id and not region and not account
            elif resource.type == "security_group":
                valid = (
                    service == "ec2"
                    and region == self.aws_region
                    and account == self.aws_account_id
                    and suffix == "security-group/" + resource.id
                )
            else:
                valid = (
                    service == "iam"
                    and not region
                    and account == self.aws_account_id
                    and suffix.startswith("role/")
                    and suffix.split("/")[-1] == resource.id
                )
            if not valid:
                raise ValueError("Resource ARN disagrees with its identity/account/region")
        return self


@dataclass
class Finding:
    rule_id: str
    resource_type: str
    resource_id: str
    resource_arn: str
    title: str
    severity: str
    expected: Any
    actual: Any
    explanation: str
    remediation: str
    cloudtrail_events: list[dict] = field(default_factory=list)


@dataclass
class ScanReport:
    aws_account_id: str
    aws_region: str
    mode: str = "live"
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    resources_selected: int = 0
    resources_checked: int = 0
    findings: list[Finding] = field(default_factory=list)
    changes: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def exit_code(self, fail_on: str = "INFO") -> int:
        if self.errors:
            return 2
        return int(
            any(SEVERITIES[f.severity] >= SEVERITIES[fail_on.upper()] for f in self.findings)
        )

    def to_dict(self) -> dict:
        result = asdict(self)
        result["schema_version"] = 1
        result["summary"] = {
            "status": "incomplete" if self.errors else "drift" if self.findings else "clean",
            "resources_selected": self.resources_selected,
            "resources_checked": self.resources_checked,
            "configuration_drift": len(self.changes),
            "findings": len(self.findings),
            "errors": len(self.errors),
            **{key.lower(): sum(f.severity == key for f in self.findings) for key in SEVERITIES},
        }
        return result

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from drift_detector.aws.common import error_message
from drift_detector.aws.ec2 import SecurityGroupCollector
from drift_detector.aws.iam import IAMCollector
from drift_detector.aws.s3 import S3Collector
from drift_detector.models import DetectorError

CLIENT_CONFIG = Config(
    connect_timeout=5, read_timeout=15, retries={"mode": "standard", "total_max_attempts": 4}
)


class AWSCollector:
    def __init__(self, baseline, profile=None, region=None, session=None):
        try:
            self.session = (
                session
                if session is not None
                else boto3.Session(profile_name=profile, region_name=region)
            )
            self.region = self.session.region_name or baseline.aws_region
            if self.region != baseline.aws_region:
                raise DetectorError(
                    f"Region mismatch: baseline={baseline.aws_region}, selected={self.region}. Select the matching region."
                )
            self.account = self.client("sts").get_caller_identity()["Account"]
            if self.account != baseline.aws_account_id:
                raise DetectorError(
                    f"Account mismatch: baseline={baseline.aws_account_id}, credentials={self.account}. Choose the correct AWS profile."
                )
        except (ClientError, BotoCoreError) as exc:
            raise DetectorError(error_message(exc)) from exc
        self._collectors = {}

    def client(self, service, region=None):
        return self.session.client(service, region_name=region or self.region, config=CLIENT_CONFIG)

    def collect(self, resource):
        if resource.type not in self._collectors:
            if resource.type == "s3":
                collector = S3Collector(self.client("s3"), self.account)
            elif resource.type == "security_group":
                collector = SecurityGroupCollector(self.client("ec2"))
            else:
                collector = IAMCollector(self.client("iam"))
            self._collectors[resource.type] = collector
        try:
            return self._collectors[resource.type].collect(resource)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucket":
                from drift_detector.models import MissingResource

                raise MissingResource from exc
            raise

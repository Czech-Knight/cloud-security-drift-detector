"""Collect complete bucket security state using bucket-owner guarded reads."""

from drift_detector.aws.common import optional_call


class S3Collector:
    def __init__(self, client, account_id: str):
        self.client, self.account_id = client, account_id

    def collect(self, resource) -> dict:
        args = {"Bucket": resource.id, "ExpectedBucketOwner": self.account_id}
        acl = self.client.get_bucket_acl(**args)  # Also proves bucket existence/access.
        owner_id = acl["Owner"]["ID"]
        grants = []
        for grant in acl["Grants"]:
            grantee = grant["Grantee"]
            identifier = grantee.get("ID", grantee.get("URI", grantee.get("EmailAddress")))
            if identifier is None:
                raise ValueError("Unsupported ACL grantee response")
            grants.append(
                {
                    "grantee": "$OWNER" if identifier == owner_id else identifier,
                    "permission": grant["Permission"],
                }
            )
        pab = optional_call(
            self.client.get_public_access_block,
            absent={"NoSuchPublicAccessBlockConfiguration"},
            default={
                "PublicAccessBlockConfiguration": {
                    key: False
                    for key in (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    )
                }
            },
            **args,
        )
        policy_response = optional_call(
            self.client.get_bucket_policy,
            absent={"NoSuchBucketPolicy"},
            default={"Policy": None},
            **args,
        )
        status = optional_call(
            self.client.get_bucket_policy_status,
            absent={"NoSuchBucketPolicy"},
            default={"PolicyStatus": {"IsPublic": False}},
            **args,
        )
        from drift_detector.baseline.normalizers import policy

        encryption_response = optional_call(
            self.client.get_bucket_encryption,
            absent={"ServerSideEncryptionConfigurationNotFoundError"},
            default=None,
            **args,
        )
        encryption = None
        if encryption_response is not None:
            rules = encryption_response["ServerSideEncryptionConfiguration"]["Rules"]
            if len(rules) != 1:
                raise ValueError("Unexpected S3 encryption response")
            defaults = rules[0]["ApplyServerSideEncryptionByDefault"]
            encryption = {
                "algorithm": defaults["SSEAlgorithm"],
                "kms_key_id": defaults.get("KMSMasterKeyID"),
                "bucket_key_enabled": rules[0].get("BucketKeyEnabled", False),
            }
        ownership = optional_call(
            self.client.get_bucket_ownership_controls,
            absent={"OwnershipControlsNotFoundError", "NoSuchOwnershipControls"},
            default=None,
            **args,
        )
        return {
            "public_access_block": pab["PublicAccessBlockConfiguration"],
            "policy": policy(policy_response["Policy"]),
            "policy_public": status["PolicyStatus"]["IsPublic"],
            "acl": grants,
            "ownership": ownership["OwnershipControls"]["Rules"][0]["ObjectOwnership"]
            if ownership
            else None,
            "encryption": encryption,
            "versioning": self.client.get_bucket_versioning(**args).get("Status", "Disabled"),
        }

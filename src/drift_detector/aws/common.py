from botocore.exceptions import ClientError

from drift_detector.models import MissingResource


def optional_call(method, *, absent: set[str], default, **kwargs):
    """Only explicit absence codes mean missing config; AccessDenied never does."""
    try:
        return method(**kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in {"NoSuchBucket"}:
            raise MissingResource from exc
        if code in absent:
            return default
        raise


def error_message(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "UnknownAWSFailure")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "403"}:
            return f"{code}: grant the documented read permissions for this resource; status is unknown, not clean."
        if code in {
            "ExpiredToken",
            "ExpiredTokenException",
            "InvalidClientTokenId",
            "UnrecognizedClientException",
        }:
            return f"{code}: refresh your AWS SSO/session credentials and retry."
        if code in {
            "PermanentRedirect",
            "AuthorizationHeaderMalformed",
            "IllegalLocationConstraintException",
        }:
            return f"{code}: confirm the bucket and configured AWS region agree."
        return f"AWS {code}: confirm access/resource state and retry; inspect CloudTrail or AWS Console if it persists."
    return f"{type(exc).__name__}: AWS credentials, connectivity or response format could not be verified. Check the setup guide and retry."

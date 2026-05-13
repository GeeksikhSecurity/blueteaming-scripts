#!/usr/bin/env python3
"""S3 public exposure detection.

Satisfies R2.1. Walks every bucket in the account, evaluates the effective
BlockPublicAccess configuration (bucket-level overrides account-level), and
reports any bucket whose configuration permits public access.

Read-only; uses `boto3` default credential chain. Required policy:
SecurityAudit or ReadOnlyAccess.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.finding import Finding, auth_error, emit, gate_exit_code  # noqa: E402

REQUIRED_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def _account_pab(s3control, account_id: str) -> dict | None:
    try:
        return s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except s3control.exceptions.NoSuchPublicAccessBlockConfiguration:
        return None


def _bucket_pab(s3, bucket: str) -> dict | None:
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except s3.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return None
        raise


def _gaps(config: dict | None) -> list[str]:
    if not config:
        return list(REQUIRED_FLAGS)
    return [flag for flag in REQUIRED_FLAGS if not config.get(flag, False)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=None, help="AWS named profile")
    args = parser.parse_args(argv)

    try:
        import boto3
        import botocore.exceptions
    except ImportError:
        auth_error("boto3 is not installed; run `pip install -r python/requirements.txt`")
        return 2

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        s3 = session.client("s3")
        s3control = session.client("s3control")
    except botocore.exceptions.NoCredentialsError:
        auth_error("no AWS credentials found")
        return 2

    account_config = _account_pab(s3control, account_id)
    account_gaps = _gaps(account_config)

    findings: list[Finding] = []
    if account_gaps:
        findings.append(
            Finding(
                id="AWS-S3-000",
                severity="HIGH",
                framework="CIS-AWS",
                control="2.1.5",
                resource=f"arn:aws:s3:::account/{account_id}",
                evidence={"missing_flags": account_gaps, "scope": "account"},
            )
        )

    for entry in s3.list_buckets().get("Buckets", []):
        bucket = entry["Name"]
        try:
            bucket_config = _bucket_pab(s3, bucket)
        except botocore.exceptions.ClientError as exc:
            sys.stderr.write(f"WARN: skipping {bucket}: {exc.response['Error']['Code']}\n")
            continue
        effective_gaps = _gaps(bucket_config) if bucket_config else account_gaps
        if effective_gaps:
            findings.append(
                Finding(
                    id="AWS-S3-001",
                    severity="HIGH",
                    framework="CIS-AWS",
                    control="2.1.5",
                    resource=f"arn:aws:s3:::{bucket}",
                    evidence={
                        "missing_flags": effective_gaps,
                        "scope": "bucket" if bucket_config else "inherited-from-account",
                    },
                )
            )

    findings.sort(key=lambda f: f.resource)
    for f in findings:
        emit(f)
    return gate_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())

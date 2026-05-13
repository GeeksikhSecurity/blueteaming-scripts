#!/usr/bin/env python3
"""IAM hygiene detections.

Satisfies requirements R2.2 (root access keys), R2.3 (stale access keys),
R2.4 (console users without MFA). Read-only; uses `boto3` default credential
chain. Required policy: SecurityAudit or ReadOnlyAccess.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

# Allow direct execution: `python python/aws/iam_hygiene.py`
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.finding import Finding, auth_error, emit, gate_exit_code  # noqa: E402

DEFAULT_KEY_AGE_DAYS = 90


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def check_root_access_keys(iam) -> list[Finding]:
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        account_id = iam.meta.client.meta.partition  # placeholder; real id below
        # Pull the real account id from STS via the same session
        sts = iam.meta.client._client_config  # noqa: SLF001 — defensive, never relied on
        try:
            import boto3

            account_id = boto3.client("sts").get_caller_identity()["Account"]
        except Exception:  # pragma: no cover — best effort
            account_id = "unknown"
        return [
            Finding(
                id="AWS-IAM-001",
                severity="CRITICAL",
                framework="CIS-AWS",
                control="1.4",
                resource=f"arn:aws:iam::{account_id}:root",
                evidence={"AccountAccessKeysPresent": True},
            )
        ]
    return []


def check_stale_access_keys(iam, max_age_days: int) -> list[Finding]:
    findings: list[Finding] = []
    paginator = iam.get_paginator("list_users")
    horizon = _now() - dt.timedelta(days=max_age_days)
    for page in paginator.paginate():
        for user in page["Users"]:
            for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                created = key["CreateDate"]
                if created < horizon:
                    findings.append(
                        Finding(
                            id="AWS-IAM-002",
                            severity="MEDIUM",
                            framework="CIS-AWS",
                            control="1.14",
                            resource=user["Arn"],
                            evidence={
                                "AccessKeyId": key["AccessKeyId"],
                                "CreateDate": created.isoformat(),
                                "AgeDays": (_now() - created).days,
                            },
                        )
                    )
    return findings


def check_console_users_without_mfa(iam) -> list[Finding]:
    findings: list[Finding] = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            try:
                iam.get_login_profile(UserName=user["UserName"])
            except iam.exceptions.NoSuchEntityException:
                continue  # no console password
            devices = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
            if not devices:
                findings.append(
                    Finding(
                        id="AWS-IAM-003",
                        severity="HIGH",
                        framework="CIS-AWS",
                        control="1.10",
                        resource=user["Arn"],
                        evidence={"ConsolePassword": True, "MFADevices": 0},
                    )
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-key-age-days",
        type=int,
        default=DEFAULT_KEY_AGE_DAYS,
        help=f"flag access keys older than this many days (default: {DEFAULT_KEY_AGE_DAYS})",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS named profile (default: boto3 default chain)",
    )
    args = parser.parse_args(argv)

    try:
        import boto3
        import botocore.exceptions
    except ImportError:
        auth_error("boto3 is not installed; run `pip install -r python/requirements.txt`")
        return 2

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        iam = session.client("iam")
        iam.get_account_summary()  # smoke test perms
    except botocore.exceptions.NoCredentialsError:
        auth_error("no AWS credentials found; configure SSO, env, or --profile")
        return 2
    except botocore.exceptions.ClientError as exc:
        auth_error(f"insufficient permissions: {exc.response['Error']['Code']}")
        return 2

    findings: list[Finding] = []
    findings += check_root_access_keys(iam)
    findings += check_stale_access_keys(iam, args.max_key_age_days)
    findings += check_console_users_without_mfa(iam)

    findings.sort(key=lambda f: (-["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(f.severity), f.resource))
    for f in findings:
        emit(f)
    return gate_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())

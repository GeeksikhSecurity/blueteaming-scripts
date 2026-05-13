#!/usr/bin/env python3
"""Pull Microsoft Defender for Cloud High-severity recommendations.

Satisfies R3.2 (one finding per recommendation per affected resource) and
R3.4 (current/target secure score emitted as INFO).

Auth: DefaultAzureCredential. Required role: Security Reader at each
subscription.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.finding import Finding, auth_error, emit, gate_exit_code  # noqa: E402


def _subscriptions(credential):
    from azure.mgmt.subscription import SubscriptionClient

    sub_client = SubscriptionClient(credential)
    return [s for s in sub_client.subscriptions.list() if s.state == "Enabled"]


def _high_recommendations(credential, subscription_id: str):
    from azure.mgmt.security import SecurityCenter

    sc = SecurityCenter(credential, subscription_id, asc_location="centralus")
    # Assessments enumerate the per-resource state of each recommendation.
    return [
        a
        for a in sc.assessments.list(scope=f"/subscriptions/{subscription_id}")
        if getattr(getattr(a, "status", None), "code", "").lower() == "unhealthy"
        and getattr(a, "metadata", None) is not None
        and getattr(a.metadata, "severity", "").lower() == "high"
    ]


def _secure_score(credential, subscription_id: str):
    from azure.mgmt.security import SecurityCenter

    sc = SecurityCenter(credential, subscription_id, asc_location="centralus")
    try:
        score = sc.secure_scores.get(secure_score_name="ascScore")
        return {
            "current": getattr(score.score, "current", None),
            "max": getattr(score.score, "max", None),
            "percentage": getattr(score.score, "percentage", None),
        }
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription", action="append", default=[])
    args = parser.parse_args(argv)

    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        auth_error("azure-identity not installed; run `pip install -r python/requirements.txt`")
        return 2

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)

    try:
        subs = _subscriptions(credential)
    except Exception as exc:
        auth_error(f"could not list subscriptions: {exc}")
        return 2

    if args.subscription:
        subs = [s for s in subs if s.subscription_id in set(args.subscription)]

    findings: list[Finding] = []

    for sub in subs:
        sub_id = sub.subscription_id

        score = _secure_score(credential, sub_id)
        if score is not None:
            findings.append(
                Finding(
                    id="AZ-DFC-INFO-001",
                    severity="INFO",
                    framework="vendor",
                    control="Defender-for-Cloud-SecureScore",
                    resource=f"/subscriptions/{sub_id}",
                    evidence={"subscription_name": sub.display_name, **score},
                )
            )

        for assessment in _high_recommendations(credential, sub_id):
            findings.append(
                Finding(
                    id="AZ-DFC-001",
                    severity="HIGH",
                    framework="vendor",
                    control=f"Defender-for-Cloud:{assessment.name}",
                    resource=assessment.resource_details.id
                    if getattr(assessment, "resource_details", None) and getattr(assessment.resource_details, "id", None)
                    else f"/subscriptions/{sub_id}",
                    evidence={
                        "display_name": assessment.display_name,
                        "description": (assessment.metadata.description or "")[:280],
                        "subscription_name": sub.display_name,
                    },
                )
            )

    findings.sort(key=lambda f: (f.severity != "INFO", f.id, f.resource))
    for f in findings:
        emit(f)
    return gate_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())

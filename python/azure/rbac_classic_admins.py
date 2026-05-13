#!/usr/bin/env python3
"""Azure RBAC discipline checks: classic admins and guest owners.

Satisfies R3.1 (classic administrators present) and R3.3 (Owner /
User Access Administrator held by a guest identity at subscription scope).

Auth: DefaultAzureCredential. Required role: Reader at each subscription
plus Directory.Read.All for resolving guest principals.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.finding import Finding, auth_error, emit, gate_exit_code  # noqa: E402

PRIVILEGED_ROLE_NAMES = {"Owner", "User Access Administrator"}


def _subscriptions(credential):
    from azure.mgmt.subscription import SubscriptionClient

    sub_client = SubscriptionClient(credential)
    return [s for s in sub_client.subscriptions.list() if s.state == "Enabled"]


def _classic_admins(credential, subscription_id: str):
    from azure.mgmt.authorization import AuthorizationManagementClient

    auth_client = AuthorizationManagementClient(credential, subscription_id)
    return list(auth_client.classic_administrators.list(api_version="2015-06-01"))


def _privileged_role_assignments(credential, subscription_id: str):
    from azure.mgmt.authorization import AuthorizationManagementClient

    auth_client = AuthorizationManagementClient(credential, subscription_id)
    scope = f"/subscriptions/{subscription_id}"
    role_defs = {
        rd.id: rd.role_name
        for rd in auth_client.role_definitions.list(scope=scope)
        if rd.role_name in PRIVILEGED_ROLE_NAMES
    }
    privileged_ids = set(role_defs.keys())
    return [
        (ra, role_defs[ra.role_definition_id])
        for ra in auth_client.role_assignments.list_for_scope(scope=scope)
        if ra.role_definition_id in privileged_ids
    ]


def _is_guest(graph_client, principal_id: str) -> bool:
    # Lightweight check: query Graph for user, look at userType. Skipped
    # gracefully when the principal is a service principal or unresolved.
    try:
        user = graph_client.users.by_user_id(principal_id).get()  # type: ignore[union-attr]
        return getattr(user, "user_type", "").lower() == "guest"
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--subscription",
        action="append",
        default=[],
        help="Limit to one or more subscription IDs (default: all enabled subscriptions)",
    )
    args = parser.parse_args(argv)

    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        auth_error("azure-identity not installed; run `pip install -r python/requirements.txt`")
        return 2

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)

    # Microsoft Graph client is optional; only used to resolve guest principals.
    graph_client = None
    try:
        from msgraph import GraphServiceClient  # type: ignore

        graph_client = GraphServiceClient(credentials=credential)
    except ImportError:
        sys.stderr.write("INFO: msgraph-sdk not installed; guest-principal resolution disabled\n")

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
        scope = f"/subscriptions/{sub_id}"

        for admin in _classic_admins(credential, sub_id):
            findings.append(
                Finding(
                    id="AZ-RBAC-001",
                    severity="HIGH",
                    framework="CIS-Azure",
                    control="1.21",
                    resource=f"{scope}/providers/Microsoft.Authorization/classicAdministrators/{admin.name}",
                    evidence={
                        "email": admin.email_address,
                        "role": admin.role,
                        "subscription_name": sub.display_name,
                    },
                )
            )

        for ra, role_name in _privileged_role_assignments(credential, sub_id):
            if graph_client and _is_guest(graph_client, ra.principal_id):
                findings.append(
                    Finding(
                        id="AZ-RBAC-002",
                        severity="HIGH",
                        framework="CIS-Azure",
                        control="1.23",
                        resource=ra.id,
                        evidence={
                            "principal_id": ra.principal_id,
                            "role": role_name,
                            "subscription_name": sub.display_name,
                            "principal_type": "Guest",
                        },
                    )
                )

    findings.sort(key=lambda f: (f.id, f.resource))
    for f in findings:
        emit(f)
    return gate_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())

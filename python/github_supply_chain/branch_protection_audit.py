#!/usr/bin/env python3
"""Audit branch protection across a GitHub organization.

Satisfies R4.1 (default branch lacks protection) and R4.2 (protection
exists but does not require PR review).

Auth: PAT or GitHub App token in GITHUB_TOKEN env var with `repo` and
`read:org` scopes.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.finding import Finding, auth_error, emit, gate_exit_code  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True, help="GitHub organization login")
    parser.add_argument(
        "--include-archived",
        action="store_true",
        help="include archived repos (default: skip)",
    )
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        auth_error("GITHUB_TOKEN env var not set; needs `repo` + `read:org`")
        return 2

    try:
        from github import Github, GithubException
    except ImportError:
        auth_error("PyGithub not installed; run `pip install -r python/requirements.txt`")
        return 2

    gh = Github(token, per_page=100)

    try:
        org = gh.get_organization(args.org)
    except GithubException as exc:
        auth_error(f"could not access org {args.org}: {exc.data.get('message', exc.status)}")
        return 2

    findings: list[Finding] = []

    for repo in org.get_repos(type="all"):
        if repo.archived and not args.include_archived:
            continue
        default_branch = repo.default_branch
        resource = f"https://github.com/{repo.full_name}/tree/{default_branch}"

        try:
            protection = repo.get_branch(default_branch).get_protection()
        except GithubException as exc:
            if exc.status == 404:
                findings.append(
                    Finding(
                        id="GH-BP-001",
                        severity="HIGH",
                        framework="NIST-CSF",
                        control="PR.IP-3",
                        resource=resource,
                        evidence={
                            "default_branch": default_branch,
                            "protection": "missing",
                            "private": repo.private,
                        },
                    )
                )
                continue
            sys.stderr.write(f"WARN: {repo.full_name}: {exc.status} {exc.data}\n")
            continue

        review = protection.required_pull_request_reviews
        if review is None or (review.required_approving_review_count or 0) < 1:
            findings.append(
                Finding(
                    id="GH-BP-002",
                    severity="HIGH",
                    framework="NIST-CSF",
                    control="PR.IP-3",
                    resource=resource,
                    evidence={
                        "default_branch": default_branch,
                        "required_approving_review_count": review.required_approving_review_count if review else 0,
                        "dismiss_stale_reviews": getattr(review, "dismiss_stale_reviews", None),
                    },
                )
            )

    findings.sort(key=lambda f: (f.id, f.resource))
    for f in findings:
        emit(f)
    return gate_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())

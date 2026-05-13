#!/usr/bin/env python3
"""Audit GitHub Actions usage across an organization.

Satisfies R4.3 (uses: pinned to a mutable ref instead of a 40-char SHA)
and R4.6 (workflow grants `permissions: write-all` or omits `permissions:`).

Auth: PAT in GITHUB_TOKEN env var with `repo` + `read:org`.

Note: first-party actions (owner == "actions") are reported at a lower
severity because the threat model is different — the immediate priority
is community/third-party actions referenced by tag.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.finding import Finding, auth_error, emit, gate_exit_code  # noqa: E402

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*uses:\s*([^\s#]+)")
PERMS_RE = re.compile(r"^\s*permissions:\s*(.*)$")
FIRST_PARTY_OWNERS = {"actions", "github"}


def _is_pinned_to_sha(ref: str) -> bool:
    return bool(SHA_RE.match(ref))


def _audit_workflow(text: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Return (uses_findings, workflow_level_perm_findings).

    uses_findings: list of (action_ref, owner, ref).
    workflow_level_perm_findings: list of issue strings.
    """
    uses_issues: list[tuple[str, str, str]] = []
    perm_issues: list[str] = []
    has_top_level_permissions = False

    for raw in text.splitlines():
        m = USES_RE.match(raw)
        if m:
            action_ref = m.group(1).strip().strip('"').strip("'")
            if "@" not in action_ref or action_ref.startswith("./") or action_ref.startswith("docker://"):
                continue
            slug, _, ref = action_ref.partition("@")
            owner = slug.split("/", 1)[0].lower() if "/" in slug else ""
            if not _is_pinned_to_sha(ref):
                uses_issues.append((action_ref, owner, ref))

        m2 = PERMS_RE.match(raw)
        if m2 and raw.startswith("permissions:"):  # top-level only
            has_top_level_permissions = True
            value = m2.group(1).strip()
            if value == "write-all":
                perm_issues.append("permissions: write-all")

    if not has_top_level_permissions:
        perm_issues.append("missing top-level permissions: block")

    return uses_issues, perm_issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True)
    parser.add_argument("--include-archived", action="store_true")
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

        try:
            wf_dir = repo.get_contents(".github/workflows")
        except GithubException:
            continue

        wf_files = wf_dir if isinstance(wf_dir, list) else [wf_dir]
        for wf in wf_files:
            if not wf.name.endswith((".yml", ".yaml")):
                continue
            try:
                content = base64.b64decode(wf.content).decode("utf-8", errors="replace")
            except Exception as exc:
                sys.stderr.write(f"WARN: {repo.full_name}/{wf.path}: decode failed ({exc})\n")
                continue

            uses_issues, perm_issues = _audit_workflow(content)

            for action_ref, owner, ref in uses_issues:
                severity = "MEDIUM" if owner in FIRST_PARTY_OWNERS else "HIGH"
                findings.append(
                    Finding(
                        id="GH-ACT-001",
                        severity=severity,
                        framework="SLSA",
                        control="action-pinning",
                        resource=f"https://github.com/{repo.full_name}/blob/{repo.default_branch}/{wf.path}",
                        evidence={"uses": action_ref, "ref": ref, "owner": owner or "unknown"},
                    )
                )

            for issue in perm_issues:
                findings.append(
                    Finding(
                        id="GH-ACT-002",
                        severity="LOW" if issue.startswith("missing") else "HIGH",
                        framework="GitHub-Actions-Hardening",
                        control="workflow-permissions",
                        resource=f"https://github.com/{repo.full_name}/blob/{repo.default_branch}/{wf.path}",
                        evidence={"issue": issue},
                    )
                )

    findings.sort(key=lambda f: (f.id, f.resource))
    for f in findings:
        emit(f)
    return gate_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())

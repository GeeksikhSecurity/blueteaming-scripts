# Design: Operational Discipline Detection Pack

## Goals

Translate the EARS requirements in [`requirements.md`](./requirements.md) into a small, composable set of read-only scripts that surface operational-discipline gaps across Entra ID, AWS, Azure, and GitHub.

## Non-goals

- Building a runtime, daemon, or scheduler. The host CI/cron handles cadence.
- Building a UI. Output is NDJSON; downstream consumers render it.
- Storing state. Each run is stateless.

## High-level architecture

```
              +------------------------+
              |  CI runner / operator  |
              +------------------------+
                         |
            +------------+------------+
            |            |            |
            v            v            v
   +---------------+  +---------+  +---------+
   | powershell/   |  | python/ |  | python/ |
   | graph/*.ps1   |  | aws/*   |  | azure/* |
   +---------------+  +---------+  +---------+
            |            |            |
            +------+-----+-----+------+
                   |           |
                   v           v
         +--------------+  +-----------------+
         | NDJSON to    |  | exit code 0/1   |
         | stdout       |  | for CI gating   |
         +--------------+  +-----------------+
                   |
                   v
           +------------------+
           | downstream:      |
           | SIEM, jq, mapper |
           | skills (PCI,     |
           | HIPAA, ISO, etc.)|
           +------------------+
```

## Module layout

```
powershell/graph/                      # M365 / Entra detections
  Find-StaleEntraAccounts.ps1
  Audit-PrivilegedRoles.ps1
  Find-MfaGaps.ps1
  Audit-OAuthConsents.ps1

python/common/finding.py               # Shared output schema (Finding dataclass + emit())

python/aws/                            # AWS detections
  iam_hygiene.py                       # R2.2, R2.3, R2.4
  s3_public_exposure.py                # R2.1

python/azure/                          # Azure detections
  rbac_classic_admins.py               # R3.1, R3.3
  defender_recommendations.py          # R3.2, R3.4

python/github_supply_chain/            # GitHub org detections
  branch_protection_audit.py           # R4.1, R4.2
  action_pinning_audit.py              # R4.3, R4.6
```

## Output schema

Every script emits one `Finding` per line on stdout.

```json
{
  "id": "string — stable per detection (e.g. AWS-IAM-001)",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "framework": "CIS-AWS | CIS-Azure | CIS-M365 | CWE | NIST-CSF | vendor",
  "control": "string — control or CWE id (e.g. 1.4, CWE-308)",
  "resource": "string — fully qualified resource identifier",
  "evidence": { "...": "..." },
  "detected_at": "ISO 8601 UTC"
}
```

### Severity mapping

| Severity | Use when |
| --- | --- |
| CRITICAL | Root keys live, public bucket with PII-likely data, privileged account without MFA |
| HIGH | Standing privilege without PIM, branch protection missing on default branch, classic admin in Azure |
| MEDIUM | Stale account, action pinned to mutable tag, Dependabot disabled |
| LOW | Workflow without explicit `permissions:` block |
| INFO | Run summary, totals, secure-score deltas |

## Auth model

| Surface | Auth strategy | Required scope/role |
| --- | --- | --- |
| Entra ID / M365 | `Connect-MgGraph` interactive or app-only via cert | `Directory.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `Application.Read.All` |
| AWS | `boto3` default credential chain | `ReadOnlyAccess` or `SecurityAudit` managed policy |
| Azure | `DefaultAzureCredential` from `azure-identity` | `Reader` at subscription, `Security Reader` at tenant root |
| GitHub | PAT or GitHub App token in `GITHUB_TOKEN` env var | `repo`, `read:org` |

Auth never lives in code. Scripts read env vars or interactive prompts; failure to authenticate exits non-zero with a remediation message (R5.4).

## Error model

- **Auth failure:** exit 2, print `ERROR: auth — <permission missing>` to stderr.
- **Transient API error (429/5xx):** exponential backoff up to 5 retries, then exit 3 with `ERROR: transient — <surface> <api>`.
- **Permanent API error (4xx other than 429):** log to stderr, continue, do not exit; the affected resource is reported as a finding with `severity: INFO` and `id: <surface>-ENUM-FAIL`.
- **Interrupt (SIGINT):** flush in-flight finding, exit 130. NDJSON remains line-valid (R6.5).

## Rate limiting

- AWS: rely on boto3 standard retry mode; cap concurrent regions at 4.
- Graph: 1 request/sec floor, batch with `$top=999` where supported.
- GitHub: respect `X-RateLimit-Remaining`; pause when remaining < 100 until reset.
- Azure ARM: 12000 reads/hour subscription cap is plenty; no extra throttling.

## Determinism & idempotency

- Findings sort by `(severity, resource)` before emission so diffs across runs are reviewable.
- `detected_at` is the only time-varying field; for diff workflows, strip it before comparing.

## Testing strategy

- **Unit:** `python/common/finding.py` round-trip serialization, severity ordering.
- **Recorded fixtures:** each detection ships with one anonymized JSON fixture under `tests/fixtures/<surface>/` and a pytest that asserts findings match a snapshot.
- **No live calls in CI:** all tests use fixtures or `moto`/`responses` mocks.
- **PowerShell:** Pester tests assert `-WhatIf` mode emits the expected findings against a mocked Graph response.

## Security considerations

- **Read-only enforcement:** PR checks grep for `Invoke-MgGraphRequest -Method POST|PUT|PATCH|DELETE` and for boto3 mutating verbs (`put_*`, `delete_*`, `create_*`); any hit fails CI unless the file lives in `examples/` (none currently).
- **Secret hygiene:** `gitleaks` or `truffleHog` pre-commit hook recommended in the host environment.
- **PII:** evidence blocks must not contain personal data beyond what's needed to identify the resource (UPN is OK as it's already in the directory).

## Roll-out plan

1. Ship scripts as in `tasks.md`.
2. Add a GitHub Actions workflow under `.github/workflows/blueteam-ci.yml` that runs `branch_protection_audit.py` against the org and posts findings as a job summary.
3. Wire to the [`compliance-to-pr`](.) skill so HIGH+ findings spawn Linear/GitHub issues.
4. Wire output to the framework-mapper skills (`pci-dss-mapper`, `hipaa-mapper`, `iso27001-mapper`) for compliance reporting.

## Open questions

- Should we add a Terraform/IaC detection module? Currently out of scope — the runtime detections are higher leverage for the operational-discipline thesis.
- Multi-tenant orchestration: today each script runs against a single tenant/account. A tiny `runner.py` that fans out across tenants is plausible but deferred until there's demand.

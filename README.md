# blueteaming-scripts

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/GeeksikhSecurity/blueteaming-scripts/badge)](https://securityscorecards.dev/viewer/?uri=github.com/GeeksikhSecurity/blueteaming-scripts) [![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/GeeksikhSecurity/blueteaming-scripts/security/policy)

Detection engineering pack targeting the failure modes that cause the vast majority of breaches: **misconfigurations, unpatched systems, third-party risk, identity mismanagement, flat networks, and poor segmentation.**

> Over 90% of security incidents trace back to the same root cause: lack of operational discipline.
> — concept credited to Yaron Levi (CISO, Dolby), surfaced via [Venture in Security](https://substack.com/@ventureinsecurity).

These scripts are not novel exploits or AI-powered anything. They surface the boring, repeatable hygiene gaps that the Verizon DBIR keeps telling us are the actual root cause.

## Scope

| Surface | Language | Auth | Focus |
| --- | --- | --- | --- |
| Microsoft 365 / Entra ID | PowerShell + Microsoft.Graph | Delegated or app, read-only | Stale accounts, MFA gaps, privileged roles, OAuth consent |
| Azure | Python + azure-mgmt-* | Default credential chain | Classic admins, Defender recommendations, RBAC |
| AWS | Python + boto3 | Default credential chain | IAM hygiene, S3 public exposure, access key age |
| GitHub org | Python + PyGithub | PAT with `repo`, `read:org` | Branch protection, action pinning, secret scanning |

## Design principles

1. **Read-only by default.** No script in this repo writes, deletes, or remediates. Every finding is informational.
2. **Evidence over alerts.** Output is structured (NDJSON) with `framework`, `control`, `resource`, `evidence`, `detected_at`.
3. **CI-gateable.** Exit code 1 when HIGH+ findings exist, so scripts double as guardrails.
4. **Small, independently shippable moves.** Each script is one detection, one concern.
5. **No internal rule names leak.** Output is safe to share with clients and stakeholders.

## Layout

```
.kiro/specs/operational-discipline/   # Kiro EARS spec set (requirements, design, tasks)
notes/                                # Theme manifesto + detection ideas
powershell/graph/                     # Microsoft Graph detections
python/aws/                           # AWS detections (boto3)
python/azure/                         # Azure detections (azure-mgmt-*)
python/github_supply_chain/           # GitHub org-level detections
python/common/                        # Shared output schema
```

## Quick start

### PowerShell (Microsoft Graph)

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "Directory.Read.All","AuditLog.Read.All","Policy.Read.All"
./powershell/graph/Find-StaleEntraAccounts.ps1 -InactiveDays 90
```

### Python

```bash
pip install -r python/requirements.txt
python python/aws/iam_hygiene.py
python python/github_supply_chain/branch_protection_audit.py --org your-org
```

## Output schema

Every script emits NDJSON to stdout, one finding per line:

```json
{"id":"AWS-IAM-001","severity":"CRITICAL","framework":"CIS-AWS","control":"1.4","resource":"arn:aws:iam::123456789012:root","evidence":{"access_keys_present":true},"detected_at":"2026-05-13T12:00:00Z"}
```

Use `jq` or pipe into your SIEM of choice.

## License

MIT. See [LICENSE](LICENSE).

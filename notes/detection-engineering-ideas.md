# Detection Engineering Ideas

Concrete detections aligned to the operational-discipline thesis. Each entry names what to detect, why it matters, and what signal source delivers it. Use this as the backlog feeder for new scripts.

## Identity (Entra ID / Microsoft 365)

| Idea | Signal source | Why |
| --- | --- | --- |
| Standing Global Administrator > 0 | Graph: `directoryRoles/Global Administrator/members` | PIM eligible-only is the target; standing GA is the highest-impact identity gap. |
| Privileged account without phishing-resistant MFA | Graph: `authenticationMethods` per privileged user | SMS/voice MFA is bypassed routinely; FIDO2/WHfB is the bar. |
| Service principal with `AppRoleAssignment` granting `Application.ReadWrite.All` | Graph: `servicePrincipals/{id}/appRoleAssignments` | Equivalent to tenant takeover via a non-human identity. |
| External (guest) user with directory role | Graph: filter `userType eq 'Guest'` joined with role assignments | Cross-tenant standing privilege is a routine pentest finding. |
| Conditional Access policy in report-only mode > 30 days | Graph: `conditionalAccess/policies` | Policy drift — the control was designed but never enforced. |
| New federation domain added | Graph audit log: `Set domain authentication` | The Solorigate pattern; high-signal even if benign. |
| Recently-consented app with Mail/Files/Directory write scope | Graph: `oauth2PermissionGrants` | The illicit-consent attack vector; rare, but high-impact. |
| User MFA method change followed by signin from new country within 24h | Graph audit log + signin log correlation | MFA bypass via self-service registration is the most common AiTM follow-up. |

## AWS

| Idea | Signal source | Why |
| --- | --- | --- |
| Root account access keys exist | IAM `GetAccountSummary` | CIS 1.4. There is no legitimate reason. |
| Access key > 90 days old on a human user | IAM `ListAccessKeys` + `GetAccessKeyLastUsed` | Key rotation discipline. |
| S3 bucket with `BlockPublicAcls=false` | S3 `GetBucketPublicAccessBlock` | The misconfig pattern behind dozens of breaches. |
| Security group allowing 0.0.0.0/0 on 22, 3389, 3306, 5432 | EC2 `DescribeSecurityGroups` | Internet-exposed admin/db ports. |
| CloudTrail not enabled or not logging to all regions | CloudTrail `DescribeTrails` | Detection itself is missing. |
| GuardDuty disabled in any active region | GuardDuty `ListDetectors` | Free-tier-eligible baseline detection turned off. |
| IAM policy with `"Resource": "*"` and `"Action": "*"` | IAM `GetPolicyVersion` | Effective `*:*` is the standing-privilege equivalent in AWS. |
| EBS snapshot or AMI shared with unknown account | EC2 `DescribeSnapshots --owner-id self` + `DescribeImages` | Cross-account exfil channel. |
| KMS key without rotation | KMS `GetKeyRotationStatus` | Cryptographic hygiene. |

## Azure

| Idea | Signal source | Why |
| --- | --- | --- |
| Classic administrators present on any subscription | ARM `Microsoft.Authorization/classicAdministrators` | Pre-RBAC standing privilege. |
| `Owner` role at subscription scope held by guest | ARM `Microsoft.Authorization/roleAssignments` | External standing admin. |
| Defender for Cloud disabled on any subscription | `Microsoft.Security/pricings` | Free-tier baseline turned off. |
| Storage account allowing public blob access | `Microsoft.Storage/storageAccounts` (`allowBlobPublicAccess`) | Azure's S3-equivalent leak vector. |
| NSG rule allowing `*` source on management ports | `Microsoft.Network/networkSecurityGroups/securityRules` | Same pattern as AWS SG audit. |
| Key Vault soft-delete or purge protection disabled | `Microsoft.KeyVault/vaults` | Ransomware-targeted destruction defense. |
| AAD `securityDefaults` disabled and no Conditional Access licensed | Graph: `policies/identitySecurityDefaultsEnforcementPolicy` | Tenants with no MFA enforcement of any kind. |

## GitHub org / supply chain

| Idea | Signal source | Why |
| --- | --- | --- |
| Default branch without protection | REST `repos/{owner}/{repo}/branches/{branch}/protection` | Anyone with write can push directly to prod. |
| Branch protection without required PR review | Same | Codifies the gap. |
| Workflow `uses:` pinned to mutable ref | Parse `.github/workflows/*.yml` | The `tj-actions/changed-files` attack class. |
| Workflow with `permissions: write-all` | Same | OIDC/secret-exfil amplifier. |
| Repo with secret scanning disabled | REST `repos/{owner}/{repo}` (`security_and_analysis`) | Free for public; cheap for private with Advanced Security. |
| Repo without `CODEOWNERS` on default branch | REST file fetch `.github/CODEOWNERS` | Review discipline gap. |
| Outside collaborator with write/admin | REST `repos/{owner}/{repo}/collaborators?affiliation=outside` | Third-party access discipline. |
| Org members not enforced to use SSO | REST `orgs/{org}/credential-authorizations` | Identity drift in the SCM. |
| Action workflow runs as `pull_request_target` with checkout of PR head | Parse workflows | The classic PWN-request pattern. |

## Patch / config drift (cross-cutting)

| Idea | Signal source | Why |
| --- | --- | --- |
| OS images older than 90 days in active use | Azure/AWS image refs in compute resources | Patch latency. |
| Container images last pushed > 180 days ago still deployed | Registry inventory + workload manifests | Same. |
| Library versions with known CVEs in deployed artifacts | SBOM + OSV (see `sbom` and `deps-enrich` skills) | Already covered by sibling skills — wire findings together. |

## Network segmentation

| Idea | Signal source | Why |
| --- | --- | --- |
| Production VPC peered with non-prod VPC | AWS `DescribeVpcPeeringConnections` + tag inspection | Flat-network attack-path amplifier. |
| Production resource reachable from sandbox subnet | Route table + SG/NSG analysis | Same as above. |

## How to prioritize new detections

Use a two-axis screen:

1. **Loss-event probability** — does the gap show up in DBIR/M-Trends as a real breach pattern?
2. **Implementation cost** — can it be a 100-line read-only script?

Detections in the top-left quadrant (high probability, low cost) ship first. The current `tasks.md` v1 set is exactly that quadrant.

Skip detections that are:
- Already covered by Defender for Cloud / Security Hub / GuardDuty out of the box (unless the script is a gap-filler that detects them being **off**).
- Dependent on log retention longer than 7 days (state-based detections are more robust than event-based for discipline checks).
- Behavioral or ML-based (different pack, different ROI profile).

## Related

- [Operational Discipline Manifesto](./operational-discipline-manifesto.md)
- Spec: [`.kiro/specs/operational-discipline/`](../.kiro/specs/operational-discipline/requirements.md)

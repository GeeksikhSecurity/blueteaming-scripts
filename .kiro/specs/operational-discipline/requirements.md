# Requirements: Operational Discipline Detection Pack

> Format: [EARS](https://alistairmavin.com/ears/) — Easy Approach to Requirements Syntax.
>
> Patterns used:
> - **Ubiquitous:** `The <system> shall <response>.`
> - **Event-driven:** `When <trigger>, the <system> shall <response>.`
> - **State-driven:** `While <state>, the <system> shall <response>.`
> - **Optional feature:** `Where <feature>, the <system> shall <response>.`
> - **Unwanted behavior:** `If <trigger>, then the <system> shall <response>.`

## Context

Per Verizon DBIR and corroborating breach reports, the dominant root cause of incidents is operational-discipline failure — misconfigurations, unpatched systems, third-party risk, identity mismanagement, flat networks, and weak segmentation. This pack detects those discipline gaps across the four highest-leverage surfaces: Entra ID, AWS, Azure, and GitHub.

## Glossary

- **Detection** — a script that compares observed state to a hygiene baseline and emits findings.
- **Finding** — a single deviation, represented as NDJSON with traceable evidence.
- **Pack** — a coherent set of detections covering one control domain.
- **Standing privilege** — a privileged role assignment that is permanently active (not just-in-time).

---

## Requirement 1: Entra ID identity hygiene

**User story:** As a security operations lead, I want to detect identity-hygiene drift in Entra ID so that I can close standing privilege, stale accounts, and MFA gaps before they are abused.

**Acceptance criteria (EARS):**

1.1 The system shall enumerate all Entra ID user accounts and report those whose `signInActivity.lastSignInDateTime` is older than the configured threshold (default 90 days) as stale.

1.2 When a user holds a directory role classified by Microsoft as privileged, the system shall report the assignment, role name, scope, and whether the assignment is eligible (PIM) or active (standing).

1.3 If a privileged account has no registered strong MFA method, then the system shall emit a CRITICAL finding mapped to CWE-308.

1.4 The system shall enumerate OAuth2 application consent grants and report any tenant-scoped grant containing `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, or `Directory.ReadWrite.All`.

1.5 While the script is executing, the system shall use only read-only Microsoft Graph scopes (`Directory.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `Application.Read.All`) and shall make no write calls.

1.6 Where Conditional Access is licensed in the tenant, the system shall report the absence of a baseline policy requiring MFA for all administrators.

---

## Requirement 2: AWS configuration hygiene

**User story:** As a cloud security engineer, I want to detect insecure defaults and posture drift in AWS so that public exposure and stale credentials are surfaced before they are exploited.

**Acceptance criteria (EARS):**

2.1 The system shall report any S3 bucket whose effective public-access configuration permits public read or write at the bucket, account, or object-ACL level.

2.2 If the AWS account has active root account access keys, then the system shall emit a CRITICAL finding mapped to CIS AWS Foundations 1.4.

2.3 The system shall report any IAM user whose active access keys are older than the configured threshold (default 90 days).

2.4 The system shall report any IAM user with console access who has no MFA device assigned.

2.5 Where AWS Security Hub is enabled in the audited account, the system shall ingest findings of severity HIGH or CRITICAL and deduplicate by control ID and resource ARN.

---

## Requirement 3: Azure configuration hygiene

**User story:** As a cloud security engineer, I want to detect insecure defaults and posture drift in Azure subscriptions so that classic admins and Defender recommendations are surfaced.

**Acceptance criteria (EARS):**

3.1 When an Azure subscription has classic administrators (co-administrators or service administrators) assigned, the system shall report each assignment as a standing-privilege violation.

3.2 The system shall enumerate Microsoft Defender for Cloud recommendations of severity High and emit one finding per recommendation per affected resource.

3.3 If any role assignment of `Owner` or `User Access Administrator` is held by an external (B2B guest) identity at subscription scope, then the system shall emit a HIGH finding.

3.4 Where Microsoft Defender for Cloud secure score is available, the system shall include the current and target score in the run summary.

---

## Requirement 4: GitHub org supply-chain discipline

**User story:** As an AppSec lead, I want to detect supply-chain discipline gaps across the GitHub org so that unprotected branches, floating-tag actions, and disabled scanning don't slip into production.

**Acceptance criteria (EARS):**

4.1 The system shall enumerate all repositories in the configured organization and report any whose default branch lacks a branch protection rule.

4.2 If a branch protection rule does not require pull-request review with at least one approving review, then the system shall emit a HIGH finding.

4.3 The system shall parse every workflow file under `.github/workflows/` in every repository and report `uses:` references pinned to a mutable ref (tag or branch) rather than a 40-character commit SHA.

4.4 When Dependabot security updates are disabled on a repository with active dependency manifests, the system shall emit a MEDIUM finding.

4.5 The system shall report any repository with secret scanning or push protection disabled where the organization plan supports them.

4.6 Where the repository has GitHub Actions enabled, the system shall report any workflow granting `permissions: write-all` or omitting an explicit `permissions:` block.

---

## Requirement 5: Evidence and reporting

**User story:** As a CISO consumer of these scripts, I want consistent evidence output so that findings can be triaged and trended without per-script glue.

**Acceptance criteria (EARS):**

5.1 The system shall emit findings as newline-delimited JSON to stdout with the fields `id`, `severity`, `framework`, `control`, `resource`, `evidence`, `detected_at`.

5.2 Where the `--format table` flag is provided, the system shall additionally render a human-readable summary table to stderr.

5.3 The system shall exit with code 0 when no findings of severity HIGH or above are present, and with a non-zero exit code otherwise, to support CI gating.

5.4 If credentials are missing or insufficient, then the system shall fail closed with a non-zero exit code and a remediation message naming the required permission or role.

5.5 The system shall map every finding to at least one external framework citation (CIS, CWE, NIST CSF, or vendor-published guidance).

---

## Requirement 6: Operating posture

**User story:** As an operator, I want these scripts to be safe to run in production so that I can schedule them without governance friction.

**Acceptance criteria (EARS):**

6.1 The system shall use only read-only API permissions across all environments.

6.2 The system shall implement client-side rate limiting and exponential backoff on HTTP 429 and 5xx responses.

6.3 The system shall not log credentials, tokens, or personally identifiable information to stdout or stderr.

6.4 Where the `--dry-run` flag is supplied, the system shall enumerate the API calls it would make without executing them.

6.5 If a script is interrupted mid-run, then partial NDJSON output emitted to stdout shall remain valid (one complete JSON object per line, no truncation of in-flight objects).

---

## Non-goals

- Active response or remediation. Every finding is read-only.
- Replacement for full CSPM or SIEM platforms. These detections are discipline checks and gap-fillers.
- Endpoint, EDR, or network-traffic-level detection.
- Novel exploit research. The pack targets the boring fundamentals; that is the point.

## Out-of-scope frameworks (future)

- PCI DSS v4.0.1 — covered separately by the `pci-dss-mapper` skill consuming this pack's output.
- HIPAA, ISO 27001, NIS2 — same pattern, mapper skills consume `findings.ndjson`.

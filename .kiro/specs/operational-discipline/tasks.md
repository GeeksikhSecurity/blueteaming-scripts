# Tasks: Operational Discipline Detection Pack

Numbered tasks trace back to the EARS requirements in [`requirements.md`](./requirements.md). Each task should land as a single reviewable commit (Tidy First: imports → types → constants → helpers → main → exports).

Format key:
- `[ ]` not started · `[~]` in progress · `[x]` done
- Each task names the file(s) it produces and the requirement IDs it satisfies.

---

## 0. Foundations

- [x] **0.1 Repo scaffold** — `README.md`, `LICENSE`, `.gitignore`, layout per `design.md`.
- [x] **0.2 Kiro spec set** — `requirements.md`, `design.md`, `tasks.md`.
- [x] **0.3 Shared output schema** — `python/common/finding.py` with `Finding` dataclass + `emit()`. _(R5.1, R6.5)_
- [x] **0.4 Python deps** — `python/requirements.txt` pinning `boto3`, `azure-identity`, `azure-mgmt-*`, `PyGithub`, `PyYAML`.

## 1. Entra ID identity hygiene _(R1)_

- [x] **1.1 Stale accounts** — `powershell/graph/Find-StaleEntraAccounts.ps1`. _(R1.1, R1.5)_
- [x] **1.2 Privileged role audit** — `powershell/graph/Audit-PrivilegedRoles.ps1`. _(R1.2, R1.5)_
- [x] **1.3 MFA gaps** — `powershell/graph/Find-MfaGaps.ps1`. _(R1.3, R1.5)_
- [x] **1.4 OAuth consent audit** — `powershell/graph/Audit-OAuthConsents.ps1`. _(R1.4, R1.5)_
- [ ] **1.5 Conditional access baseline check** — `powershell/graph/Test-CaBaseline.ps1`. _(R1.6)_

## 2. AWS configuration hygiene _(R2)_

- [x] **2.1 S3 public exposure** — `python/aws/s3_public_exposure.py`. _(R2.1)_
- [x] **2.2 IAM hygiene** — `python/aws/iam_hygiene.py` covering root keys, key age, MFA-less console users. _(R2.2, R2.3, R2.4)_
- [ ] **2.3 Security Hub ingest** — `python/aws/security_hub_ingest.py`. _(R2.5)_

## 3. Azure configuration hygiene _(R3)_

- [x] **3.1 Classic admins & guest owners** — `python/azure/rbac_classic_admins.py`. _(R3.1, R3.3)_
- [x] **3.2 Defender recommendations** — `python/azure/defender_recommendations.py`. _(R3.2, R3.4)_

## 4. GitHub org supply-chain discipline _(R4)_

- [x] **4.1 Branch protection audit** — `python/github_supply_chain/branch_protection_audit.py`. _(R4.1, R4.2)_
- [x] **4.2 Action pinning audit** — `python/github_supply_chain/action_pinning_audit.py`. _(R4.3, R4.6)_
- [ ] **4.3 Dependabot/secret scanning audit** — `python/github_supply_chain/scanning_audit.py`. _(R4.4, R4.5)_

## 5. CI gating & reporting _(R5, R6)_

- [ ] **5.1 GitHub Actions workflow** — `.github/workflows/blueteam-ci.yml` runs branch_protection_audit against the org weekly.
- [ ] **5.2 NDJSON validator** — `python/common/validate_ndjson.py` for CI sanity.
- [ ] **5.3 Severity-gated exit** — extract to shared helper used by all Python scripts. _(R5.3)_
- [ ] **5.4 Dry-run support** — uniform `--dry-run` flag across Python scripts. _(R6.4)_

## 6. Compliance integration

- [ ] **6.1 PCI DSS mapping** — feed `findings.ndjson` into the `pci-dss-mapper` skill, link the resulting report.
- [ ] **6.2 HIPAA mapping** — same pattern via `hipaa-mapper`.
- [ ] **6.3 ISO 27001 mapping** — same pattern via `iso27001-mapper`.

## 7. Documentation

- [x] **7.1 Operational discipline manifesto** — `notes/operational-discipline-manifesto.md`.
- [x] **7.2 Detection engineering ideas** — `notes/detection-engineering-ideas.md`.
- [ ] **7.3 Per-script READMEs** — usage + required permissions per script.
- [ ] **7.4 Threat model** — `notes/threat-model.md` covering the scripts themselves (least-privilege, credential leakage, output handling).

---

## Acceptance gate

Pack is "v1" when sections 0–4 are complete and at least one finding from each surface has been triaged successfully end-to-end through a downstream mapper skill (section 6).

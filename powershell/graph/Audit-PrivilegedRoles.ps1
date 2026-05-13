<#
.SYNOPSIS
    Enumerate Entra ID privileged role assignments and flag standing (non-PIM) holders.

.DESCRIPTION
    Satisfies R1.2 (privileged role audit with PIM-vs-standing) and R1.5 (read-only).
    For each Microsoft-classified privileged role, lists who holds it and emits a
    HIGH finding when the assignment is active (standing) rather than eligible.

    Connect:
        Connect-MgGraph -Scopes "Directory.Read.All","RoleManagement.Read.Directory"

.PARAMETER PrivilegedRolesOnly
    If set, only emit findings for roles flagged isPrivileged=true. Default true.

.OUTPUTS
    NDJSON Finding objects.
#>

[CmdletBinding()]
param(
    [switch]$PrivilegedRolesOnly = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    Write-Error "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Directory.Read.All','RoleManagement.Read.Directory'"
    exit 2
}

$detectedAt = (Get-Date).ToUniversalTime().ToString("o")

# Role definitions tell us which roles Microsoft considers privileged.
$roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
$privRoleIds = @{}
foreach ($r in $roleDefs) {
    if ($r.IsPrivileged -or -not $PrivilegedRolesOnly) {
        $privRoleIds[$r.Id] = $r
    }
}

# Active assignments (standing privilege).
$activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All

# Eligible assignments (PIM-eligible, not standing) — used for INFO findings.
try {
    $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
} catch {
    $eligibleAssignments = @()
    Write-Information "PIM not licensed or unavailable; eligibility data skipped." -InformationAction Continue
}

$findings = @()

foreach ($a in $activeAssignments) {
    if (-not $privRoleIds.ContainsKey($a.RoleDefinitionId)) { continue }
    $role = $privRoleIds[$a.RoleDefinitionId]
    $findings += [pscustomobject]@{
        id          = 'M365-ID-002'
        severity    = 'HIGH'
        framework   = 'CIS-M365'
        control     = '1.1.3'
        resource    = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$($a.Id)"
        evidence    = @{
            roleName       = $role.DisplayName
            roleTemplateId = $role.TemplateId
            principalId    = $a.PrincipalId
            scope          = $a.DirectoryScopeId
            assignmentType = 'active-standing'
        }
        detected_at = $detectedAt
    }
}

foreach ($a in $eligibleAssignments) {
    if (-not $privRoleIds.ContainsKey($a.RoleDefinitionId)) { continue }
    $role = $privRoleIds[$a.RoleDefinitionId]
    $findings += [pscustomobject]@{
        id          = 'M365-ID-002-INFO'
        severity    = 'INFO'
        framework   = 'CIS-M365'
        control     = '1.1.3'
        resource    = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules/$($a.Id)"
        evidence    = @{
            roleName       = $role.DisplayName
            roleTemplateId = $role.TemplateId
            principalId    = $a.PrincipalId
            scope          = $a.DirectoryScopeId
            assignmentType = 'eligible-pim'
        }
        detected_at = $detectedAt
    }
}

foreach ($f in $findings) {
    $f | ConvertTo-Json -Compress -Depth 6
}

$standingCount = ($findings | Where-Object { $_.evidence.assignmentType -eq 'active-standing' }).Count
Write-Information "Privileged roles audited. Standing assignments: $standingCount." -InformationAction Continue

if ($standingCount -gt 0) { exit 1 } else { exit 0 }

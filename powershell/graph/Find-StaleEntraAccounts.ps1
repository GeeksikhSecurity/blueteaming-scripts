<#
.SYNOPSIS
    Find Entra ID user accounts whose last interactive sign-in is older than a threshold.

.DESCRIPTION
    Satisfies R1.1 (stale account detection) and R1.5 (read-only Graph scopes).
    Emits one NDJSON finding per stale user to the pipeline; writes a human-readable
    summary to the information stream.

    Connect first:
        Connect-MgGraph -Scopes "Directory.Read.All","AuditLog.Read.All"

.PARAMETER InactiveDays
    Number of days of inactivity that qualifies an account as stale. Default 90.

.PARAMETER IncludeDisabled
    Include accounts where AccountEnabled is false. Default: skip disabled accounts.

.OUTPUTS
    NDJSON Finding objects on the success stream.

.EXAMPLE
    Connect-MgGraph -Scopes "Directory.Read.All","AuditLog.Read.All"
    ./Find-StaleEntraAccounts.ps1 -InactiveDays 90 | Tee-Object findings.ndjson
#>

[CmdletBinding()]
param(
    [int]$InactiveDays = 90,
    [switch]$IncludeDisabled
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    Write-Error "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Directory.Read.All','AuditLog.Read.All'"
    exit 2
}

$threshold = (Get-Date).ToUniversalTime().AddDays(-$InactiveDays)
$detectedAt = (Get-Date).ToUniversalTime().ToString("o")

$select = "id,userPrincipalName,displayName,accountEnabled,signInActivity,createdDateTime"
$users = Get-MgUser -All -Property $select -ConsistencyLevel eventual

$stale = foreach ($u in $users) {
    if (-not $IncludeDisabled -and -not $u.AccountEnabled) { continue }
    $last = $u.SignInActivity.LastSignInDateTime
    if ($null -eq $last) {
        # Never signed in: stale if account is older than threshold.
        if ($u.CreatedDateTime -gt $threshold) { continue }
        $reason = 'never-signed-in'
    } elseif ($last -lt $threshold) {
        $reason = 'signin-older-than-threshold'
    } else {
        continue
    }

    [pscustomobject]@{
        id          = 'M365-ID-001'
        severity    = 'MEDIUM'
        framework   = 'CIS-M365'
        control     = '1.1.1'
        resource    = "https://graph.microsoft.com/v1.0/users/$($u.Id)"
        evidence    = @{
            userPrincipalName = $u.UserPrincipalName
            displayName       = $u.DisplayName
            accountEnabled    = $u.AccountEnabled
            lastSignInDateTime = if ($last) { $last.ToString("o") } else { $null }
            createdDateTime   = $u.CreatedDateTime.ToString("o")
            reason            = $reason
            thresholdDays     = $InactiveDays
        }
        detected_at = $detectedAt
    }
}

# Emit NDJSON
foreach ($f in $stale) {
    $f | ConvertTo-Json -Compress -Depth 6
}

Write-Information "Found $($stale.Count) stale accounts (threshold $InactiveDays days)." -InformationAction Continue

if ($stale.Count -gt 0) { exit 1 } else { exit 0 }

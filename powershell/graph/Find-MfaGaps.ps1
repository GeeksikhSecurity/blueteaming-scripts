<#
.SYNOPSIS
    Find privileged Entra ID accounts without a strong MFA method registered.

.DESCRIPTION
    Satisfies R1.3 (CRITICAL finding when a privileged account lacks strong MFA, CWE-308)
    and R1.5 (read-only).

    "Strong" methods are FIDO2 security key, Windows Hello for Business, Microsoft
    Authenticator passwordless / phone sign-in, and certificate-based auth.
    SMS, voice, and email are not counted as strong.

    Connect:
        Connect-MgGraph -Scopes "Directory.Read.All","UserAuthenticationMethod.Read.All","RoleManagement.Read.Directory"
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    Write-Error "Not connected to Microsoft Graph."
    exit 2
}

$detectedAt = (Get-Date).ToUniversalTime().ToString("o")

$strongMethodTypes = @(
    '#microsoft.graph.fido2AuthenticationMethod'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
    '#microsoft.graph.x509CertificateAuthenticationMethod'
)

# Privileged principals via active role assignments on privileged roles.
$roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All | Where-Object { $_.IsPrivileged }
$privRoleIds = @{}
foreach ($r in $roleDefs) { $privRoleIds[$r.Id] = $r }

$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All |
    Where-Object { $privRoleIds.ContainsKey($_.RoleDefinitionId) }

$principalIds = $assignments.PrincipalId | Sort-Object -Unique

$findings = @()
foreach ($pid in $principalIds) {
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $pid -ErrorAction Stop
    } catch {
        # Likely a service principal, not a user.
        continue
    }
    $hasStrong = $false
    foreach ($m in $methods) {
        if ($strongMethodTypes -contains $m.AdditionalProperties['@odata.type']) {
            $hasStrong = $true
            break
        }
    }
    if (-not $hasStrong) {
        try { $user = Get-MgUser -UserId $pid -Property "id,userPrincipalName,displayName" } catch { $user = $null }
        $findings += [pscustomobject]@{
            id          = 'M365-ID-003'
            severity    = 'CRITICAL'
            framework   = 'CWE'
            control     = 'CWE-308'
            resource    = "https://graph.microsoft.com/v1.0/users/$pid"
            evidence    = @{
                userPrincipalName = if ($user) { $user.UserPrincipalName } else { $null }
                displayName       = if ($user) { $user.DisplayName } else { $null }
                registeredMethods = $methods | ForEach-Object { $_.AdditionalProperties['@odata.type'] }
            }
            detected_at = $detectedAt
        }
    }
}

foreach ($f in $findings) {
    $f | ConvertTo-Json -Compress -Depth 6
}

Write-Information "Privileged accounts without strong MFA: $($findings.Count)" -InformationAction Continue
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }

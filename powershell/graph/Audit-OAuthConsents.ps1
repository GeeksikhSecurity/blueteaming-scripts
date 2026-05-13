<#
.SYNOPSIS
    Audit OAuth2 application consent grants in Entra ID for high-impact scopes.

.DESCRIPTION
    Satisfies R1.4: enumerate oauth2PermissionGrants (delegated) and appRoleAssignments
    (application), report any tenant-scoped grant containing high-impact scopes.

    Connect:
        Connect-MgGraph -Scopes "Directory.Read.All","Application.Read.All"
#>

[CmdletBinding()]
param(
    [string[]]$HighImpactScopes = @(
        'Mail.ReadWrite',
        'Mail.Send',
        'Files.ReadWrite.All',
        'Directory.ReadWrite.All',
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    Write-Error "Not connected to Microsoft Graph."
    exit 2
}

$detectedAt = (Get-Date).ToUniversalTime().ToString("o")
$findings = @()

# Delegated grants
$grants = Get-MgOauth2PermissionGrant -All
foreach ($g in $grants) {
    # 'AllPrincipals' means tenant-wide consent
    if ($g.ConsentType -ne 'AllPrincipals') { continue }
    $scopes = ($g.Scope -split '\s+') | Where-Object { $_ -in $HighImpactScopes }
    if ($scopes.Count -eq 0) { continue }
    try {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $g.ClientId
        $appName = $sp.DisplayName
    } catch { $appName = $null }
    $findings += [pscustomobject]@{
        id          = 'M365-ID-004'
        severity    = 'HIGH'
        framework   = 'CIS-M365'
        control     = '5.1.5'
        resource    = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.Id)"
        evidence    = @{
            grantType        = 'delegated'
            clientAppId      = $g.ClientId
            clientAppName    = $appName
            consentType      = $g.ConsentType
            highImpactScopes = @($scopes)
        }
        detected_at = $detectedAt
    }
}

# Application (app-role) grants — these grant tenant-wide app permissions.
$servicePrincipals = Get-MgServicePrincipal -All -Property "id,displayName,appId,servicePrincipalType"
foreach ($sp in $servicePrincipals) {
    try {
        $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction Stop
    } catch { continue }
    foreach ($ar in $appRoles) {
        try {
            $resource = Get-MgServicePrincipal -ServicePrincipalId $ar.ResourceId
        } catch { continue }
        $appRoleDef = $resource.AppRoles | Where-Object { $_.Id -eq $ar.AppRoleId }
        if (-not $appRoleDef) { continue }
        if ($appRoleDef.Value -notin $HighImpactScopes) { continue }
        $findings += [pscustomobject]@{
            id          = 'M365-ID-005'
            severity    = 'HIGH'
            framework   = 'CIS-M365'
            control     = '5.1.5'
            resource    = "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)"
            evidence    = @{
                grantType         = 'application'
                clientAppName     = $sp.DisplayName
                clientAppId       = $sp.AppId
                resourceAppName   = $resource.DisplayName
                appRoleValue      = $appRoleDef.Value
                appRoleDisplayName = $appRoleDef.DisplayName
            }
            detected_at = $detectedAt
        }
    }
}

foreach ($f in $findings) {
    $f | ConvertTo-Json -Compress -Depth 6
}

Write-Information "High-impact consent grants: $($findings.Count)" -InformationAction Continue
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }

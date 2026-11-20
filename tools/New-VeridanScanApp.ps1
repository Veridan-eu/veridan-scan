
<#
.SYNOPSIS
  Registers the multi-tenant public client app "Veridan Scan" in VERIDAN'S OWN tenant. Run once, by Vasil.

.DESCRIPTION
  The free Zorgplicht Scan (Invoke-VeridanCollection.ps1 -Mode Free) signs in as the customer's own administrator.
  Today it does that through Microsoft's "Microsoft Graph Command Line Tools" app. A Veridan-owned, publisher-verified
  app shows the customer "Veridan" (a verified publisher) on the consent screen instead. This script creates that app.

  What it creates (one application object, nothing else):
    - displayName 'Veridan Scan', signInAudience AzureADMultipleOrgs (any Entra tenant);
    - a PUBLIC client: isFallbackPublicClient true, redirect URI http://localhost (interactive, delegated sign-in);
    - requiredResourceAccess: the eight DELEGATED Microsoft Graph scopes of the collector, resolved by VALUE at run
      time from the Graph service principal's oauth2PermissionScopes (Directory.Read.All, Policy.Read.All,
      AuditLog.Read.All, Application.Read.All, Reports.Read.All, RoleManagement.Read.Directory,
      DeviceManagementConfiguration.Read.All, Organization.Read.All); refused if Graph has none of them by that name;
    - info: marketing, privacy statement and terms of service URLs (parameters, veridan.eu defaults);
    - NO client secret, NO certificate, NO application (app-only) permission. It cannot read anything by itself:
      it only acts as the signed-in customer administrator, after that administrator consents.

  Safety:
    - -TenantId is required (no default). After sign-in (Application.ReadWrite.All, -ContextScope Process) the
      script reads the tenant's verified domains and REFUSES unless they contain -ExpectedDomain (default
      'veridan.eu'), and unless the sign-in tenant is the one asked for. It then disconnects. This tool must never
      create an app in a client's tenant.
    - It refuses if an application named 'Veridan Scan' already exists (and prints that app's appId).
    - -WhatIf signs in, reads, runs every check, prints the exact body it would send and creates nothing.
    - It creates no service principal, grants no consent and changes nothing else.

  After it has run (manual steps, also printed at the end):
    1. Publisher domain: set it to veridan.eu if it is not already (Entra admin center > App registrations >
       Veridan Scan > Branding & properties).
    2. Publisher verification: same blade, "Add MPN ID to verify publisher", with the Partner One ID (the partner
       global account of Veridan's Microsoft AI Cloud Partner Program account).
    3. Put the appId into $VERIDAN_SCAN_APP_ID in Invoke-VeridanCollection.ps1 in a follow-up PR (a release decision).

.EXAMPLE
  .\New-VeridanScanApp.ps1 -TenantId <veridan.eu tenant id> -WhatIf
  .\New-VeridanScanApp.ps1 -TenantId <veridan.eu tenant id>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [string] $ExpectedDomain = 'veridan.eu',
    [string] $DisplayName = 'Veridan Scan',
    [string] $MarketingUrl = 'https://veridan.eu',
    [string] $PrivacyUrl = 'https://veridan.eu/privacy/',
    [string] $TermsUrl = 'https://veridan.eu/terms/'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-VsaGraphAppId { '00000003-0000-0000-c000-000000000000' }
function Get-VsaGraphBase { 'https://graph.microsoft.com/v1.0' }

function Write-Item { param([string]$m) Write-Host "   $m" -ForegroundColor DarkGray }

function Get-VsaPermissionNames {
    # The collector's $scopes, delegated and read-only; tests/ScanApp.Tests.ps1 keeps the two lists equal.
    return @('Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Application.Read.All',
             'Reports.Read.All', 'RoleManagement.Read.Directory',
             'DeviceManagementConfiguration.Read.All', 'Organization.Read.All')
}

function Get-VsaDelegatedScopeIds {
    # Resolves the eight scope names to Microsoft Graph delegated-permission (oauth2PermissionScope) ids, by value.
    param([scriptblock] $Invoke)
    $sp = (& $Invoke 'GET' "$(Get-VsaGraphBase)/servicePrincipals?`$filter=appId eq '$(Get-VsaGraphAppId)'&`$select=id,oauth2PermissionScopes" $null).value
    if (-not $sp -or @($sp).Count -ne 1) { throw 'Refusing: the Microsoft Graph service principal was not found in the tenant.' }
    $byName = @{}
    foreach ($s in @($sp)[0].oauth2PermissionScopes) { $byName[$s.value] = $s.id }
    $ids = @()
    foreach ($n in (Get-VsaPermissionNames)) {
        if (-not $byName.ContainsKey($n)) { throw "Refusing: Microsoft Graph has no delegated permission '$n'." }
        $ids += $byName[$n]
    }
    return $ids
}

function New-VsaBody {
    param([string] $DisplayName, [string] $MarketingUrl, [string] $PrivacyUrl, [string] $TermsUrl, [string[]] $ScopeIds)
    # No passwordCredentials, no keyCredentials, no app-only (Role) permission: a public client has no secret.
    return @{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMultipleOrgs'
        isFallbackPublicClient = $true
        publicClient           = @{ redirectUris = @('http://localhost') }
        requiredResourceAccess = @(@{
            resourceAppId  = (Get-VsaGraphAppId)
            resourceAccess = @($ScopeIds | ForEach-Object { @{ id = $_; type = 'Scope' } })
        })
        info                   = @{ marketingUrl = $MarketingUrl; privacyStatementUrl = $PrivacyUrl; termsOfServiceUrl = $TermsUrl }
    }
}

function Invoke-VsaRegistration {
    # Every check, then the create. Throws (the caller prints REFUSED and disconnects) on any refusal.
    # Returns @{ Status = 'Created' | 'WhatIf'; AppId; Body }.
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $TenantId, [string] $ConnectedTenantId, [string] $ExpectedDomain, [string] $DisplayName,
          [string] $MarketingUrl, [string] $PrivacyUrl, [string] $TermsUrl, [scriptblock] $Invoke)

    # 1. Is this Veridan's own tenant? Before anything about applications is read or written.
    if ("$ConnectedTenantId".ToLowerInvariant() -ne "$TenantId".ToLowerInvariant()) {
        throw "Refusing: asked for tenant $TenantId, but the Graph context is $ConnectedTenantId."
    }
    $org = @((& $Invoke 'GET' "$(Get-VsaGraphBase)/organization?`$select=id,verifiedDomains" $null).value)
    if ($org.Count -ne 1) { throw 'Refusing: could not read the tenant organization.' }
    if ("$($org[0].id)".ToLowerInvariant() -ne "$TenantId".ToLowerInvariant()) {
        throw "Refusing: the organization id $($org[0].id) is not the requested tenant $TenantId."
    }
    $domains = @($org[0].verifiedDomains | ForEach-Object { "$($_.name)".ToLowerInvariant() })
    if ($domains -notcontains "$ExpectedDomain".ToLowerInvariant()) {
        throw "Refusing: this tenant has no verified domain $ExpectedDomain (it has: $($domains -join ', ')). This tool only registers the app in Veridan's own tenant, never in a client tenant."
    }
    Write-Item "tenant $TenantId owns $ExpectedDomain"

    # 2. Idempotency: one 'Veridan Scan' only.
    $existing = @((& $Invoke 'GET' "$(Get-VsaGraphBase)/applications?`$filter=displayName eq '$($DisplayName -replace "'", "''")'&`$select=id,appId,displayName" $null).value)
    if ($existing.Count -gt 0) {
        throw "Refusing: an application named '$DisplayName' already exists (appId $($existing[0].appId)). Use that appId; nothing was created."
    }

    # 3. The body, scopes resolved by value from this tenant's Graph service principal.
    $scopeIds = Get-VsaDelegatedScopeIds -Invoke $Invoke
    $body = New-VsaBody -DisplayName $DisplayName -MarketingUrl $MarketingUrl -PrivacyUrl $PrivacyUrl -TermsUrl $TermsUrl -ScopeIds $scopeIds

    if (-not $PSCmdlet.ShouldProcess("tenant $TenantId", "create application '$DisplayName' (multi-tenant public client, 8 delegated Graph scopes)")) {
        return [pscustomobject]@{ Status = 'WhatIf'; AppId = $null; Body = $body }
    }
    $app = & $Invoke 'POST' "$(Get-VsaGraphBase)/applications" $body
    Write-Item "application $($app.appId) created"
    return [pscustomobject]@{ Status = 'Created'; AppId = $app.appId; Body = $body }
}

# ==================================================================== main
if ($MyInvocation.InvocationName -eq '.') { return }    # dot-sourced: functions only

$invoke = { param([string]$Method, [string]$Uri, $Body)
    if ($null -ne $Body) { Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json' }
    else { Invoke-MgGraphRequest -Method $Method -Uri $Uri } }

$exit = 0
try {
    Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All' -ContextScope Process -NoWelcome
    $r = Invoke-VsaRegistration -TenantId $TenantId -ConnectedTenantId (Get-MgContext).TenantId -ExpectedDomain $ExpectedDomain `
        -DisplayName $DisplayName -MarketingUrl $MarketingUrl -PrivacyUrl $PrivacyUrl -TermsUrl $TermsUrl -Invoke $invoke -WhatIf:$WhatIfPreference
    if ($r.Status -eq 'WhatIf') {
        Write-Host ''
        Write-Host 'WhatIf: nothing was created. This is the body that would be sent to POST /applications:' -ForegroundColor Cyan
        Write-Host ($r.Body | ConvertTo-Json -Depth 10)
    } else {
        Write-Host ''
        Write-Host "Created '$DisplayName'. Application (client) id:" -ForegroundColor Green
        Write-Host "  $($r.AppId)"
        Write-Host ''
        Write-Host 'Next, by hand (nothing is done for you):' -ForegroundColor Cyan
        Write-Host '  1. Entra admin center > App registrations > Veridan Scan > Branding & properties: set the publisher domain to veridan.eu if it is not already.'
        Write-Host '  2. Same blade, "Add MPN ID to verify publisher": enter the Partner One ID (the partner global account of the Microsoft AI Cloud Partner Program account).'
        Write-Host "  3. Put the appId into `$VERIDAN_SCAN_APP_ID in Invoke-VeridanCollection.ps1, in a follow-up PR (a release decision)."
    }
} catch {
    Write-Host "REFUSED: $($_.Exception.Message)"
    $exit = 2
} finally {
    try { Disconnect-MgGraph | Out-Null } catch { }
}
exit $exit

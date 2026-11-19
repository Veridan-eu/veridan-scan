#Requires -Version 7.0
<#
.SYNOPSIS
  Creates - and removes again - the temporary read-only access that a Full scan needs in a client's tenant.

.DESCRIPTION
  Full mode of Invoke-VeridanCollection.ps1 signs in app-only with a certificate. This script sets that up for
  one engagement and takes it down afterwards (D-AG-073 item 7: access is removed after every scan and granted
  again for the next one, unless the client asks otherwise).

  Create (default):
    - an app registration in the client's tenant with exactly the collector's eight read-only Microsoft Graph
      application permissions, a neutral name and no client secret;
    - its service principal;
    - a self-signed certificate, valid -ValidDays (default 14, at most 30), whose private key is created
      non-exportable in Cert:\CurrentUser\My on this machine only; the public part goes into the app.
    It does NOT grant admin consent. It prints the consent link: a Privileged Role Administrator or Global
    Administrator of the client approves the eight permissions there (Graph application permissions need one of
    those two roles). It then prints the -ClientId and -CertificateThumbprint for the collector.

  Remove (-Remove -ClientId <app id>):
    - deletes the app (Entra deletes its service principal with it) and purges it from the recycle bin;
    - deletes the certificate from Cert:\CurrentUser\My;
    - checks that no app, no service principal, no recycle-bin entry and no certificate is left, and exits 1
      naming what is left if anything is.

  Sign-in: delegated, as an administrator of the client tenant, with Application.ReadWrite.All only,
  -ContextScope Process, and Disconnect-MgGraph at the end. The tenant is checked after sign-in against
  -TenantId and against forbidden-tenants.txt next to this script, before anything is created or deleted.
  The default sign-in is interactive (a browser window, or Web Account Manager on Windows). -UseDeviceCode signs in
  with a code on another device instead, for a console without a window (SSH, server core, a remote shell). Many
  tenants block that flow: Security Defaults (AADSTS530035) or a Conditional Access policy on authentication flows.
  If it is blocked, run the script in a normal PowerShell 7 window instead; do not weaken the client's policy.

  If a create fails, the script deletes and purges the half-made app and removes the local certificate; it warns
  about anything it could not remove, and the original error is shown.

.EXAMPLE
  .\New-VeridanAccess.ps1 -TenantId <guid>
  .\Invoke-VeridanCollection.ps1 -Mode Full -TenantId <guid> -ClientId <app id> -CertificateThumbprint <thumb>
  .\New-VeridanAccess.ps1 -TenantId <guid> -Remove -ClientId <app id>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [switch] $Remove,
    [switch] $UseDeviceCode,   # sign in with a code on another device (no browser window here: SSH, server core)
    [string] $ClientId,
    [int] $ValidDays = 14,
    [string] $DisplayName = 'Read-only configuration review'
)

function Get-VdaGraphAppId { '00000003-0000-0000-c000-000000000000' }
function Get-VdaGraphBase { 'https://graph.microsoft.com/v1.0' }

function Write-Item { param([string]$m) Write-Host "   $m" -ForegroundColor DarkGray }

function Get-VdaPermissionNames {
    # The collector's $scopes, read-only; tests/Access.Tests.ps1 keeps the two lists equal.
    return @('Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Application.Read.All',
             'Reports.Read.All', 'RoleManagement.Read.Directory',
             'DeviceManagementConfiguration.Read.All', 'Organization.Read.All')
}

function Get-VdaField {
    # A field of a Graph response, whether it arrived as a hashtable (Invoke-MgGraphRequest) or an object; $null if absent.
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value } else { return $null }
}

function ConvertTo-VdaKeyId {
    # Certificate thumbprint (40 hex) -> Graph customKeyIdentifier (base64 of the 20 bytes).
    param([string] $Thumbprint)
    $bytes = [byte[]]::new($Thumbprint.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($Thumbprint.Substring(2 * $i, 2), 16) }
    return [Convert]::ToBase64String($bytes)
}

function ConvertFrom-VdaKeyId {
    # Graph customKeyIdentifier -> thumbprint (40 upper-case hex), or $null if it is not a 20-byte identifier.
    param($KeyId)
    if (-not $KeyId) { return $null }
    try { $b = [Convert]::FromBase64String("$KeyId") } catch { return $null }
    if ($b.Length -ne 20) { return $null }
    return (($b | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-VdaValidDays {
    param([int] $Requested)
    if ($Requested -le 0) { return 14 }
    if ($Requested -gt 30) { throw "Refusing: -ValidDays $Requested; the certificate may be valid for at most 30 days." }
    return $Requested
}

function Get-VdaForbiddenTenantIds {
    # Same rule as the collector (O-9): GUIDs only, comments and anything else ignored, lower-cased.
    param([string] $Path = (Join-Path $PSScriptRoot 'forbidden-tenants.txt'))
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $ids = @(Get-Content -LiteralPath $Path | ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
             Where-Object { $_ -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' } |
             ForEach-Object { $_.ToLowerInvariant() })
    Write-Item "forbidden-tenants.txt: $($ids.Count) tenant(s) refused on this machine"
    return $ids
}

function Assert-VdaTenantAllowed {
    param([string] $Connected, [string] $Requested, [string[]] $Forbidden = @())
    $c = "$Connected".ToLowerInvariant()
    if (-not $c) { throw 'Refusing: the Graph context has no tenant id.' }
    if ($Requested -and $c -ne "$Requested".ToLowerInvariant()) {
        throw "Refusing: asked for tenant $Requested, but the Graph context is $Connected."
    }
    if ($Forbidden -contains $c) {
        throw "Refusing: tenant $Connected is listed in forbidden-tenants.txt on this machine."
    }
}

function Get-VdaGraphRoleIds {
    # Resolves the eight permission names to Microsoft Graph application-role ids in this tenant.
    param([scriptblock] $Invoke)
    $sp = (& $Invoke 'GET' "$(Get-VdaGraphBase)/servicePrincipals?`$filter=appId eq '$(Get-VdaGraphAppId)'&`$select=id,appRoles" $null).value
    if (-not $sp -or @($sp).Count -ne 1) { throw 'Microsoft Graph service principal not found in the tenant.' }
    $byName = @{}
    foreach ($r in @($sp)[0].appRoles) { if (@($r.allowedMemberTypes) -contains 'Application') { $byName[$r.value] = $r.id } }
    $ids = @()
    foreach ($n in (Get-VdaPermissionNames)) {
        if (-not $byName.ContainsKey($n)) { throw "Microsoft Graph has no application permission '$n'." }
        $ids += $byName[$n]
    }
    return $ids
}

function New-VdaAccess {
    param([string] $TenantId, [string] $DisplayName, [int] $ValidDays, [scriptblock] $Invoke, [hashtable] $Cert)
    $days = Get-VdaValidDays -Requested $ValidDays
    $roleIds = Get-VdaGraphRoleIds -Invoke $Invoke
    $notAfter = (Get-Date).AddDays($days)
    $c = & $Cert.new "CN=$DisplayName" $notAfter
    $app = $null
    try {
    # Graph checks the key's dates against the certificate itself: use the certificate's own NotBefore/NotAfter (whole
    # seconds in the store), never the Get-Date value it was asked for (milliseconds) - KeyCredentialsInvalidEndDate on T2.
    $start = if ($c.PSObject.Properties['NotBefore'] -and $c.NotBefore) { [datetime]$c.NotBefore } else { (Get-Date) }
    $end = if ($c.PSObject.Properties['NotAfter'] -and $c.NotAfter) { [datetime]$c.NotAfter } else { $notAfter }
    Write-Item "certificate $($c.Thumbprint) (Cert:\CurrentUser\My, valid until $($end.ToString('yyyy-MM-dd')))"
    $body = @{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMyOrg'
        requiredResourceAccess = @(@{
            resourceAppId  = (Get-VdaGraphAppId)
            resourceAccess = @($roleIds | ForEach-Object { @{ id = $_; type = 'Role' } })
        })
        keyCredentials         = @(@{
            customKeyIdentifier = ConvertTo-VdaKeyId -Thumbprint $c.Thumbprint     # lets -Remove find the local certificate
            type        = 'AsymmetricX509Cert'
            usage       = 'Verify'
            key         = [Convert]::ToBase64String($c.RawData)
            displayName = "CN=$DisplayName"
            startDateTime = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
            endDateTime   = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        })
    }
        $app = & $Invoke 'POST' "$(Get-VdaGraphBase)/applications" $body
        Write-Item "app registration $($app.appId)"
        $null = & $Invoke 'POST' "$(Get-VdaGraphBase)/servicePrincipals" @{ appId = $app.appId }
        Write-Item 'service principal created'
    } catch {
        # a failed create leaves nothing: the half-made app (deleted, purged, its SP goes with it) and the local certificate.
        # Cleanup problems are reported, never allowed to replace the original error.
        $original = $_
        if ($app -and $app.appId) {
            try {
                $left = @(Remove-VdaAccess -ClientId $app.appId -Invoke $Invoke -Cert $Cert)
                if ($left.Count) { Write-Warning "create failed and cleanup left: $($left -join '; ')" }
            } catch { Write-Warning "create failed and cleanup of app $($app.appId) failed: $($_.Exception.Message)" }
        } elseif (-not $app) {
            Write-Warning "create failed before an app id came back; if an app named '$DisplayName' exists in the tenant, remove it by hand"
        }
        try { if (& $Cert.exists $c.Thumbprint) { & $Cert.remove $c.Thumbprint; Write-Item "certificate $($c.Thumbprint) removed (create failed)" } }
        catch { Write-Warning "create failed and certificate $($c.Thumbprint) could not be removed: $($_.Exception.Message)" }
        throw $original
    }
    return [pscustomobject]@{
        ClientId              = $app.appId
        CertificateThumbprint = $c.Thumbprint
        NotAfter              = $end
        ConsentUrl            = "https://login.microsoftonline.com/$TenantId/adminconsent?client_id=$($app.appId)"
    }
}

function Get-VdaLeftovers {
    param([string] $ClientId, [string[]] $Thumbprints, [string[]] $DeletedIds, [scriptblock] $Invoke, [hashtable] $Cert)
    $left = @()
    if (@((& $Invoke 'GET' "$(Get-VdaGraphBase)/applications?`$filter=appId eq '$ClientId'&`$select=id" $null).value).Count -gt 0) {
        $left += "app registration $ClientId"
    }
    if (@((& $Invoke 'GET' "$(Get-VdaGraphBase)/servicePrincipals?`$filter=appId eq '$ClientId'&`$select=id" $null).value).Count -gt 0) {
        $left += "service principal of $ClientId"
    }
    foreach ($d in $DeletedIds) {
        $inBin = $true
        try { $null = & $Invoke 'GET' "$(Get-VdaGraphBase)/directory/deletedItems/$d" $null } catch { $inBin = $false }
        if ($inBin) { $left += "recycle-bin entry $d" }
    }
    foreach ($t in $Thumbprints) { if (& $Cert.exists $t) { $left += "certificate $t in Cert:\CurrentUser\My" } }
    return $left
}

function Remove-VdaAccess {
    param([string] $ClientId, [scriptblock] $Invoke, [hashtable] $Cert)
    $apps = @((& $Invoke 'GET' "$(Get-VdaGraphBase)/applications?`$filter=appId eq '$ClientId'&`$select=id,appId,keyCredentials" $null).value)
    $thumbs = @(); $deleted = @()
    foreach ($a in $apps) {
        foreach ($k in @(Get-VdaField $a 'keyCredentials')) {
            $t = ConvertFrom-VdaKeyId -KeyId (Get-VdaField $k 'customKeyIdentifier')
            if ($t) { $thumbs += $t }
        }
        $null = & $Invoke 'DELETE' "$(Get-VdaGraphBase)/applications/$($a.id)" $null
        Write-Item "app registration $ClientId deleted"
        try { $null = & $Invoke 'DELETE' "$(Get-VdaGraphBase)/directory/deletedItems/$($a.id)" $null; Write-Item 'purged from the recycle bin' }
        catch { Write-Item "recycle bin: $($_.Exception.Message)" }
        $deleted += $a.id
    }
    foreach ($t in $thumbs) { if (& $Cert.exists $t) { & $Cert.remove $t; Write-Item "certificate $t removed" } }
    return @(Get-VdaLeftovers -ClientId $ClientId -Thumbprints $thumbs -DeletedIds $deleted -Invoke $Invoke -Cert $Cert)
}

# ==================================================================== main
if ($MyInvocation.InvocationName -eq '.') { return }    # dot-sourced: functions only

$certApi = @{
    new    = { param($Subject, $NotAfter)
               New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' `
                   -KeyExportPolicy NonExportable -KeySpec Signature -KeyAlgorithm RSA -KeyLength 2048 `
                   -HashAlgorithm SHA256 -NotAfter $NotAfter }
    exists = { param($Thumbprint) Test-Path -LiteralPath "Cert:\CurrentUser\My\$Thumbprint" }
    remove = { param($Thumbprint) Remove-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint" -DeleteKey }
}
$invoke = { param([string]$Method, [string]$Uri, $Body)
    if ($null -ne $Body) { Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json' }
    else { Invoke-MgGraphRequest -Method $Method -Uri $Uri } }

if ($Remove -and -not $ClientId) { throw '-Remove needs -ClientId (the app id printed when the access was created).' }
$forbidden = Get-VdaForbiddenTenantIds
if ($forbidden -contains $TenantId.ToLowerInvariant()) { throw "Refusing: tenant $TenantId is listed in forbidden-tenants.txt on this machine." }

$exit = 0
try {
    $connect = @{ TenantId = $TenantId; Scopes = 'Application.ReadWrite.All'; ContextScope = 'Process'; NoWelcome = $true }
    if ($UseDeviceCode) { $connect.UseDeviceCode = $true }
    Connect-MgGraph @connect
    Assert-VdaTenantAllowed -Connected (Get-MgContext).TenantId -Requested $TenantId -Forbidden $forbidden
    if ($Remove) {
        $left = @(Remove-VdaAccess -ClientId $ClientId -Invoke $invoke -Cert $certApi)
        if ($left.Count -eq 0) { Write-Host "Removed: nothing of $ClientId is left in the tenant or on this machine." -ForegroundColor Green }
        else { Write-Host "NOT fully removed - still there: $($left -join '; ')" -ForegroundColor Red; $exit = 1 }
    } else {
        $r = New-VdaAccess -TenantId $TenantId -DisplayName $DisplayName -ValidDays $ValidDays -Invoke $invoke -Cert $certApi
        Write-Host ''
        Write-Host 'Next: a Privileged Role Administrator or Global Administrator of the client approves the permissions:' -ForegroundColor Cyan
        Write-Host "  $($r.ConsentUrl)"
        Write-Host 'Then run the Full scan:' -ForegroundColor Cyan
        Write-Host "  .\Invoke-VeridanCollection.ps1 -Mode Full -TenantId $TenantId -ClientId $($r.ClientId) -CertificateThumbprint $($r.CertificateThumbprint)"
        Write-Host 'Afterwards remove the access:' -ForegroundColor Cyan
        Write-Host "  .\New-VeridanAccess.ps1 -TenantId $TenantId -Remove -ClientId $($r.ClientId)"
        Write-Host "The certificate expires on $($r.NotAfter.ToString('yyyy-MM-dd')) in any case."
    }
} finally {
    try { Disconnect-MgGraph | Out-Null } catch { }
}
exit $exit

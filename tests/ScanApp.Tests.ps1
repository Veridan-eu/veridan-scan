
# tests/ScanApp.Tests.ps1 - tools/New-VeridanScanApp.ps1 (registers the multi-tenant public client app "Veridan Scan"
# in Veridan's OWN tenant). The script's functions are extracted via the PowerShell AST and run against a fake Graph;
# nothing here signs in, calls Connect-MgGraph or touches a real tenant.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\New-VeridanScanApp.ps1'
$collector = (Resolve-Path (Join-Path $PSScriptRoot '..\Invoke-VeridanCollection.ps1')).Path

function Assert-That([bool]$cond, [string]$msg) { if (-not $cond) { throw "FAIL: $msg" } }
function Assert-Throws([scriptblock]$sb, [string]$like, [string]$msg) {
    $thrown = $null
    try { & $sb } catch { $thrown = $_.Exception.Message }
    if ($null -eq $thrown) { throw "FAIL: $msg (nothing was thrown)" }
    if ($like -and $thrown -notlike $like) { throw "FAIL: $msg (got: $thrown)" }
}

Assert-That (Test-Path -LiteralPath $script) 'tools\New-VeridanScanApp.ps1 exists'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw "parse errors: $(($parseErrors | ForEach-Object { $_.Message }) -join '; ')" }
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
function Write-Item { param([string]$m) }   # silence the script's progress lines

$own     = '11111111-1111-4111-8111-111111111111'
$foreign = '99999999-9999-4999-8999-999999999999'
$graphSp = 'aaaaaaaa-0000-4000-8000-000000000001'

# --- 1. the eight scopes are exactly the collector's $scopes ---
$cAst = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$null)
$assign = $cAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$scopes' }, $true) | Select-Object -First 1
$collectorScopes = @(([scriptblock]::Create($assign.Right.Extent.Text)).Invoke()) | Sort-Object
$ours = @(Get-VsaPermissionNames) | Sort-Object
Assert-That ($ours.Count -eq 8) "eight delegated scopes (got $($ours.Count))"
Assert-That ($null -eq (Compare-Object $collectorScopes $ours)) 'the scope list equals the collector $scopes'
Assert-That (@($ours | Where-Object { $_ -notlike '*.Read*' }).Count -eq 0) 'every scope is read-only'

# --- a fake Graph in "veridan.eu"'s tenant ---
$scopeIds = @{}
foreach ($n in (Get-VsaPermissionNames)) { $scopeIds[$n] = [guid]::NewGuid().ToString() }
function New-FakeGraph([string[]] $domains = @('veridan.eu', 'veridan.onmicrosoft.com'), [string] $orgId = $own, [string[]] $existingNames = @(), [string[]] $missingScopes = @()) {
    $state = @{ calls = New-Object System.Collections.ArrayList; posts = New-Object System.Collections.ArrayList }
    $invoke = {
        param([string]$Method, [string]$Uri, $Body)
        [void]$state.calls.Add("$Method $Uri")
        if ($Method -eq 'GET' -and $Uri -like '*/organization*') {
            return @{ value = @(@{ id = $orgId; verifiedDomains = @($domains | ForEach-Object { @{ name = $_; isDefault = $false } }) }) }
        }
        if ($Method -eq 'GET' -and $Uri -like '*/applications?*') {
            if ($existingNames -contains 'Veridan Scan') { return @{ value = @(@{ id = 'obj-1'; appId = '44444444-4444-4444-8444-444444444444'; displayName = 'Veridan Scan' }) } }
            return @{ value = @() }
        }
        if ($Method -eq 'GET' -and $Uri -like "*servicePrincipals?*00000003-0000-0000-c000-000000000000*") {
            return @{ value = @(@{ id = $graphSp; oauth2PermissionScopes = @($scopeIds.Keys | Where-Object { $missingScopes -notcontains $_ } | ForEach-Object { @{ value = $_; id = $scopeIds[$_]; type = 'Admin' } }) + @(@{ value = 'User.Read'; id = [guid]::NewGuid().ToString(); type = 'User' }) }) }
        }
        if ($Method -eq 'POST' -and $Uri -like '*/applications') {
            [void]$state.posts.Add($Body)
            return @{ id = 'obj-new'; appId = '55555555-5555-4555-8555-555555555555' }
        }
        throw "fake Graph: unexpected $Method $Uri"
    }.GetNewClosure()
    return @{ state = $state; invoke = $invoke }
}
function Register($g, [string] $connected = $own, [switch] $WhatIf, [string] $expected = 'veridan.eu') {
    Invoke-VsaRegistration -TenantId $own -ConnectedTenantId $connected -ExpectedDomain $expected -DisplayName 'Veridan Scan' `
        -MarketingUrl 'https://veridan.eu' -PrivacyUrl 'https://veridan.eu/privacy/' -TermsUrl 'https://veridan.eu/terms/' `
        -Invoke $g.invoke -WhatIf:$WhatIf
}

# --- 2. a tenant that does not own the expected domain is refused, nothing is created ---
$g = New-FakeGraph -domains @('client.example', 'client.onmicrosoft.com') -orgId $own
Assert-Throws { Register $g } '*veridan.eu*' 'a tenant without the expected verified domain is refused'
Assert-That ($g.state.posts.Count -eq 0) 'nothing created in a foreign tenant'
Assert-That (@($g.state.calls | Where-Object { $_ -like '*/applications*' }).Count -eq 0) 'the foreign tenant is refused before any application call'
# a lookalike domain is not the domain
$g = New-FakeGraph -domains @('notveridan.eu', 'veridan.eu.evil.example')
Assert-Throws { Register $g } '*veridan.eu*' 'a lookalike domain is refused (exact match only)'
# the signed-in tenant must be the one asked for
$g = New-FakeGraph
Assert-Throws { Register $g -connected $foreign } '*asked for tenant*' 'the Graph context must be the requested tenant'
$g = New-FakeGraph -orgId $foreign
Assert-Throws { Register $g } '*organization*' 'the organization id must be the requested tenant'
Assert-That ($g.state.posts.Count -eq 0) 'nothing created on a tenant mismatch'
# domain compare is case-insensitive
$g = New-FakeGraph -domains @('VERIDAN.EU')
$r = Register $g -WhatIf
Assert-That ($r.Status -eq 'WhatIf') 'the domain match ignores case'

# --- 3. an existing "Veridan Scan" app: refused, its appId printed in the message ---
$g = New-FakeGraph -existingNames @('Veridan Scan')
Assert-Throws { Register $g } '*44444444-4444-4444-8444-444444444444*' 'an existing app is refused and its appId is in the message'
Assert-That ($g.state.posts.Count -eq 0) 'nothing created when the app exists'

# --- 4. a scope Graph does not have: refused ---
$g = New-FakeGraph -missingScopes @('Reports.Read.All')
Assert-Throws { Register $g } '*Reports.Read.All*' 'a missing delegated scope is refused, named'
Assert-That ($g.state.posts.Count -eq 0) 'nothing created when a scope is missing'

# --- 5. the body: multi-tenant, public client, eight DELEGATED scopes resolved by value, no credentials ---
$g = New-FakeGraph
$r = Register $g
Assert-That ($r.Status -eq 'Created' -and $r.AppId -eq '55555555-5555-4555-8555-555555555555') 'created, appId returned'
Assert-That ($g.state.posts.Count -eq 1) 'exactly one POST'
$b = $g.state.posts[0]
Assert-That ($b.displayName -eq 'Veridan Scan') 'displayName'
Assert-That ($b.signInAudience -eq 'AzureADMultipleOrgs') 'multi-tenant'
Assert-That ($b.isFallbackPublicClient -eq $true) 'public client'
Assert-That (@($b.publicClient.redirectUris).Count -eq 1 -and $b.publicClient.redirectUris[0] -eq 'http://localhost') 'redirect URI http://localhost'
Assert-That ($b.info.marketingUrl -eq 'https://veridan.eu' -and $b.info.privacyStatementUrl -eq 'https://veridan.eu/privacy/' -and $b.info.termsOfServiceUrl -eq 'https://veridan.eu/terms/') 'info URLs'
Assert-That (@($b.requiredResourceAccess).Count -eq 1 -and $b.requiredResourceAccess[0].resourceAppId -eq '00000003-0000-0000-c000-000000000000') 'one resource: Microsoft Graph'
$acc = @($b.requiredResourceAccess[0].resourceAccess)
Assert-That ($acc.Count -eq 8) "eight permissions (got $($acc.Count))"
Assert-That (@($acc | Where-Object { $_.type -ne 'Scope' }).Count -eq 0) 'every permission is delegated (Scope), none is app-only (Role)'
$wantIds = @($scopeIds.Values) | Sort-Object
Assert-That ($null -eq (Compare-Object @($acc | ForEach-Object { $_.id } | Sort-Object) $wantIds)) 'the ids are the ones Graph returned for the eight names (resolved by value)'
foreach ($k in 'passwordCredentials', 'keyCredentials', 'requiredAppRoles') {
    Assert-That (-not $b.ContainsKey($k)) "the body has no $k"
}
Assert-That (($b | ConvertTo-Json -Depth 10) -notmatch 'Role') 'no application (app-only) permission anywhere in the body'

# --- 6. -WhatIf creates nothing but returns the exact body ---
$g = New-FakeGraph
$r = Register $g -WhatIf
Assert-That ($r.Status -eq 'WhatIf') '-WhatIf: status'
Assert-That ($g.state.posts.Count -eq 0) '-WhatIf: no POST'
Assert-That (@($g.state.calls | Where-Object { $_ -notlike 'GET *' }).Count -eq 0) '-WhatIf: only reads'
Assert-That ($r.Body.signInAudience -eq 'AzureADMultipleOrgs' -and @($r.Body.requiredResourceAccess[0].resourceAccess).Count -eq 8) '-WhatIf returns the body that would be sent'

# --- 7. the script itself: parameters ---
$params = $ast.ParamBlock.Parameters
$tenantParam = $params | Where-Object { $_.Name.VariablePath.UserPath -eq 'TenantId' }
Assert-That ($null -ne $tenantParam -and $tenantParam.Attributes.Extent.Text -match 'Mandatory') '-TenantId is mandatory (no default)'
$dom = $params | Where-Object { $_.Name.VariablePath.UserPath -eq 'ExpectedDomain' }
Assert-That ($dom.DefaultValue.Extent.Text -eq "'veridan.eu'") "-ExpectedDomain defaults to 'veridan.eu'"
Assert-That ($ast.ParamBlock.Attributes.Extent.Text -match 'SupportsShouldProcess') 'the script supports -WhatIf'

Write-Host 'ScanApp.Tests.ps1: OK'
exit 0

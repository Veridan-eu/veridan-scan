# tests/Access.Tests.ps1 - New-VeridanAccess.ps1 (D-AG-073 item 7: access is removed after every Full scan).
# Extracts the script's functions via the PowerShell AST and runs them against a fake Graph and a fake
# certificate store - nothing here signs in or touches a real tenant.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script = (Resolve-Path (Join-Path $PSScriptRoot '..\New-VeridanAccess.ps1')).Path
$collector = (Resolve-Path (Join-Path $PSScriptRoot '..\Invoke-VeridanCollection.ps1')).Path

$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw "parse errors: $(($parseErrors | ForEach-Object { $_.Message }) -join '; ')" }

function Assert-That([bool]$cond, [string]$msg) { if (-not $cond) { throw "FAIL: $msg" } }
function Assert-Throws([scriptblock]$sb, [string]$like, [string]$msg) {
    $thrown = $null
    try { & $sb } catch { $thrown = $_.Exception.Message }
    if ($null -eq $thrown) { throw "FAIL: $msg (nothing was thrown)" }
    if ($like -and $thrown -notlike $like) { throw "FAIL: $msg (got: $thrown)" }
}

# every function of the script, defined in this scope (the main block does not run)
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
function Write-Item { param([string]$m) }   # silence the script's progress lines

# --- 1. the permissions are exactly the collector's eight read scopes ---
$cAst = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$null)
$assign = $cAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -eq '$scopes' }, $true) | Select-Object -First 1
Assert-That ($null -ne $assign) 'the collector assigns $scopes'
$collectorScopes = @(([scriptblock]::Create($assign.Right.Extent.Text)).Invoke()) | Sort-Object
$ours = @(Get-VdaPermissionNames) | Sort-Object
Assert-That ($ours.Count -eq 8) "eight permissions (got $($ours.Count))"
Assert-That ((Compare-Object $collectorScopes $ours) -eq $null) 'the permission list equals the collector $scopes'
Assert-That (@($ours | Where-Object { $_ -notlike '*.Read*' }).Count -eq 0) 'every permission is read-only'

# --- 2. forbidden tenants are refused before anything happens ---
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("vda-" + [guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
    $list = Join-Path $tmp 'forbidden-tenants.txt'
    Set-Content -LiteralPath $list -Value @('# production', '056C256C-0000-4000-8000-000000000001  # prod', 'not-a-guid')
    $forbidden = @(Get-VdaForbiddenTenantIds -Path $list)
    Assert-That ($forbidden.Count -eq 1 -and $forbidden[0] -eq '056c256c-0000-4000-8000-000000000001') 'the list is read, lower-cased, comments and non-GUIDs ignored'
    Assert-Throws { Assert-VdaTenantAllowed -Connected '056c256c-0000-4000-8000-000000000001' -Requested '056c256c-0000-4000-8000-000000000001' -Forbidden $forbidden } '*forbidden-tenants*' 'a listed tenant is refused'
    Assert-Throws { Assert-VdaTenantAllowed -Connected '11111111-1111-4111-8111-111111111111' -Requested '22222222-2222-4222-8222-222222222222' -Forbidden @() } '*asked for tenant*' 'a different signed-in tenant is refused'
    Assert-Throws { Assert-VdaTenantAllowed -Connected '' -Requested '22222222-2222-4222-8222-222222222222' -Forbidden @() } '*no tenant*' 'an empty context is refused'
    Assert-VdaTenantAllowed -Connected '22222222-2222-4222-8222-222222222222' -Requested '22222222-2222-4222-8222-222222222222' -Forbidden $forbidden
} finally { Remove-Item -Recurse -Force $tmp }

# --- validity: 1..30 days, default 14 ---
Assert-That ((Get-VdaValidDays -Requested 0) -eq 14) 'default 14 days'
Assert-That ((Get-VdaValidDays -Requested 7) -eq 7) '7 days kept'
Assert-Throws { Get-VdaValidDays -Requested 31 } '*30*' 'more than 30 days refused'

# --- a fake Graph ---
$graphSpId = 'aaaaaaaa-0000-4000-8000-000000000001'
$roles = @{}
foreach ($n in (Get-VdaPermissionNames)) { $roles[$n] = [guid]::NewGuid().ToString() }
function New-FakeGraph {
    $state = @{ apps = @{}; sps = @{}; deleted = @{}; calls = New-Object System.Collections.ArrayList; leaveSp = $false }
    $invoke = {
        param([string]$Method, [string]$Uri, $Body)
        [void]$state.calls.Add("$Method $Uri")
        if ($Method -eq 'GET' -and $Uri -like '*servicePrincipals?$filter=appId eq ''00000003-0000-0000-c000-000000000000''*') {
            return @{ value = @(@{ id = $graphSpId; appRoles = @($roles.Keys | ForEach-Object { @{ value = $_; id = $roles[$_]; allowedMemberTypes = @('Application') } }) }) }
        }
        if ($Method -eq 'POST' -and $Uri -like '*/applications') {
            $id = [guid]::NewGuid().ToString(); $appId = [guid]::NewGuid().ToString()
            $state.apps[$appId] = @{ id = $id; appId = $appId; body = $Body }
            return @{ id = $id; appId = $appId }
        }
        if ($Method -eq 'POST' -and $Uri -like '*/servicePrincipals') {
            $spid = [guid]::NewGuid().ToString(); $state.sps[$Body.appId] = $spid
            return @{ id = $spid; appId = $Body.appId }
        }
        if ($Method -eq 'GET' -and $Uri -match "applications\?\`$filter=appId eq '([0-9a-f-]+)'") {
            $a = $Matches[1]
            if ($state.apps.ContainsKey($a)) { return @{ value = @(@{ id = $state.apps[$a].id; appId = $a; keyCredentials = $state.apps[$a].body.keyCredentials }) } }
            return @{ value = @() }
        }
        if ($Method -eq 'GET' -and $Uri -match "servicePrincipals\?\`$filter=appId eq '([0-9a-f-]+)'") {
            $a = $Matches[1]
            if ($state.sps.ContainsKey($a)) { return @{ value = @(@{ id = $state.sps[$a]; appId = $a }) } }
            return @{ value = @() }
        }
        if ($Method -eq 'DELETE' -and $Uri -match '/applications/([0-9a-f-]+)$') {
            $oid = $Matches[1]
            foreach ($k in @($state.apps.Keys)) {
                if ($state.apps[$k].id -eq $oid) {
                    $state.deleted[$oid] = $k; $state.apps.Remove($k)
                    if (-not $state.leaveSp) { $state.sps.Remove($k) }
                }
            }
            return $null
        }
        if ($Method -eq 'GET' -and $Uri -match '/directory/deletedItems/([0-9a-f-]+)$') {
            if ($state.deleted.ContainsKey($Matches[1])) { return @{ id = $Matches[1] } }
            throw 'Request_ResourceNotFound'
        }
        if ($Method -eq 'DELETE' -and $Uri -match '/directory/deletedItems/([0-9a-f-]+)$') {
            $state.deleted.Remove($Matches[1]); return $null
        }
        throw "fake Graph: unexpected $Method $Uri"
    }.GetNewClosure()
    return @{ state = $state; invoke = $invoke }
}

# --- a fake certificate store ---
$certs = @{}
$certApi = @{
    new    = { param($Subject, $NotAfter) $t = ([guid]::NewGuid().ToString('N') + '00000000').Substring(0, 40).ToUpperInvariant(); $certs[$t] = $Subject
               return [pscustomobject]@{ Thumbprint = $t; NotAfter = $NotAfter; RawData = [byte[]](1, 2, 3) } }
    exists = { param($Thumbprint) return $certs.ContainsKey($Thumbprint.ToUpperInvariant()) }
    remove = { param($Thumbprint) $certs.Remove($Thumbprint.ToUpperInvariant()) }
}

# --- 3. create: app with the eight application roles, a short certificate, a service principal, no consent ---
$g = New-FakeGraph
$r = New-VdaAccess -TenantId '22222222-2222-4222-8222-222222222222' -DisplayName 'Read-only configuration review' -ValidDays 14 -Invoke $g.invoke -Cert $certApi
Assert-That ($g.state.apps.Count -eq 1) 'one application created'
$body = $g.state.apps[$r.ClientId].body
Assert-That ($body.displayName -eq 'Read-only configuration review') 'neutral display name'
Assert-That ($body.displayName -notmatch '(?i)lab|collector') 'no "lab" or "collector" in the name'
$rra = @($body.requiredResourceAccess)
Assert-That ($rra.Count -eq 1 -and $rra[0].resourceAppId -eq '00000003-0000-0000-c000-000000000000') 'only Microsoft Graph is requested'
$ids = @($rra[0].resourceAccess | ForEach-Object { $_.id }) | Sort-Object
Assert-That ((Compare-Object $ids (@($roles.Values) | Sort-Object)) -eq $null) 'exactly the eight role ids'
Assert-That (@($rra[0].resourceAccess | Where-Object { $_.type -ne 'Role' }).Count -eq 0) 'application permissions (Role), not delegated'
Assert-That (@($body.keyCredentials).Count -eq 1 -and $body.keyCredentials[0].type -eq 'AsymmetricX509Cert') 'one certificate credential, no secret'
Assert-That (-not ($body.Keys -contains 'passwordCredentials') -or @($body.passwordCredentials).Count -eq 0) 'no client secret'
Assert-That ((ConvertFrom-VdaKeyId -KeyId $body.keyCredentials[0].customKeyIdentifier) -eq $r.CertificateThumbprint) 'the key id carries the certificate thumbprint (so -Remove finds it)'
Assert-That ($null -eq (ConvertFrom-VdaKeyId -KeyId 'AQID')) 'a key id that is not 20 bytes is ignored'
Assert-That ($g.state.sps.ContainsKey($r.ClientId)) 'service principal created'
Assert-That (@($g.state.calls | Where-Object { $_ -like '*appRoleAssignments*' -or $_ -like '*oauth2PermissionGrants*' }).Count -eq 0) 'the script never grants consent itself'
Assert-That ($certs.ContainsKey($r.CertificateThumbprint)) 'certificate in the (fake) CurrentUser store'
Assert-That (($r.NotAfter - (Get-Date)).TotalDays -le 14.01 -and ($r.NotAfter - (Get-Date)).TotalDays -gt 13.9) 'certificate valid 14 days'
Assert-That ($r.ConsentUrl -eq "https://login.microsoftonline.com/22222222-2222-4222-8222-222222222222/adminconsent?client_id=$($r.ClientId)") 'admin consent link for this tenant and app'

# --- 4. remove: app, service principal, recycle bin and certificate gone, and checked ---
$left = Remove-VdaAccess -ClientId $r.ClientId -Invoke $g.invoke -Cert $certApi
Assert-That (@($left).Count -eq 0) "nothing left after -Remove (left: $(@($left) -join ', '))"
Assert-That ($g.state.apps.Count -eq 0 -and $g.state.sps.Count -eq 0 -and $g.state.deleted.Count -eq 0) 'app, SP and recycle-bin entry gone'
Assert-That (-not $certs.ContainsKey($r.CertificateThumbprint)) 'certificate removed from the store'

# --- 5. remove reports whatever is still there ---
$g2 = New-FakeGraph
$g2.state.leaveSp = $true
$r2 = New-VdaAccess -TenantId '22222222-2222-4222-8222-222222222222' -DisplayName 'Read-only configuration review' -ValidDays 3 -Invoke $g2.invoke -Cert $certApi
$left2 = @(Remove-VdaAccess -ClientId $r2.ClientId -Invoke $g2.invoke -Cert $certApi)
Assert-That ($left2.Count -eq 1 -and $left2[0] -like 'service principal*') "a leftover service principal is reported (got: $($left2 -join ', '))"

# --- 6. remove of an unknown app id: nothing to delete, and nothing found ---
$g3 = New-FakeGraph
$left3 = @(Remove-VdaAccess -ClientId '33333333-3333-4333-8333-333333333333' -Invoke $g3.invoke -Cert $certApi)
Assert-That ($left3.Count -eq 0) 'unknown app id: nothing left to report'

# --- 6b. key dates come from the certificate itself (T2, 19.11: KeyCredentialsInvalidEndDate) ---
$certDated = @{
    new    = { param($Subject, $NotAfter) $t = ([guid]::NewGuid().ToString('N') + '00000000').Substring(0, 40).ToUpperInvariant(); $certs[$t] = $Subject
               # the store keeps whole seconds and backdates NotBefore; the requested $NotAfter has milliseconds
               return [pscustomobject]@{ Thumbprint = $t; NotBefore = [datetime]'2026-11-19T20:55:52'; NotAfter = [datetime]'2026-12-03T21:05:25'; RawData = [byte[]](1, 2, 3) } }
    exists = $certApi.exists
    remove = $certApi.remove
}
$g4 = New-FakeGraph
$r4 = New-VdaAccess -TenantId '22222222-2222-4222-8222-222222222222' -DisplayName 'Read-only configuration review' -ValidDays 14 -Invoke $g4.invoke -Cert $certDated
$k4 = $g4.state.apps[$r4.ClientId].body.keyCredentials[0]
$inv = [Globalization.CultureInfo]::InvariantCulture
Assert-That ($k4.endDateTime -eq ([datetime]'2026-12-03T21:05:25').ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv)) "endDateTime is the certificate's NotAfter in UTC (got $($k4.endDateTime))"
Assert-That ($k4.startDateTime -eq ([datetime]'2026-11-19T20:55:52').ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv)) "startDateTime is the certificate's NotBefore in UTC (got $($k4.startDateTime))"
Assert-That ($k4.endDateTime -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') 'whole seconds, UTC, Z suffix'
$null = Remove-VdaAccess -ClientId $r4.ClientId -Invoke $g4.invoke -Cert $certDated

# --- 6c. a failed create leaves nothing and shows the original error ---
$g5 = New-FakeGraph
$inner = $g5.invoke
$failSp = { param([string]$Method, [string]$Uri, $Body)
    if ($Method -eq 'POST' -and $Uri -like '*/servicePrincipals') { throw 'boom: service principal' }
    & $inner $Method $Uri $Body }.GetNewClosure()
$before = @($certs.Keys)
Assert-Throws { New-VdaAccess -TenantId '22222222-2222-4222-8222-222222222222' -DisplayName 'Read-only configuration review' -ValidDays 14 -Invoke $failSp -Cert $certApi 3>$null } '*boom: service principal*' 'the original error is rethrown'
Assert-That ($g5.state.apps.Count -eq 0) 'the half-made app is deleted'
Assert-That ($g5.state.deleted.Count -eq 0) 'and purged from the recycle bin'
Assert-That (@($certs.Keys | Where-Object { $before -notcontains $_ }).Count -eq 0) 'the new local certificate is removed'

# --- 7. source invariants ---
$src = Get-Content -Raw -LiteralPath $script
Assert-That ($src -match "-ContextScope Process") 'signs in with -ContextScope Process'
Assert-That ($src -match 'Disconnect-MgGraph') 'disconnects at the end'
Assert-That ($src -match "CurrentUser\\My") 'the key stays in CurrentUser\My'
Assert-That ($src -match 'NonExportable') 'the key is not exportable'
Assert-That ($src -notmatch '(?i)passwordCredentials\s*=\s*@\(\s*@') 'no client secret is ever created'

Write-Host 'Access.Tests.ps1: all assertions passed' -ForegroundColor Green
exit 0

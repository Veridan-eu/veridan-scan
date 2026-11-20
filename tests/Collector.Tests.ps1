# tests/Collector.Tests.ps1 - /verify collector, Task 1 (spec rev 3, section 5).
# Extracts Get-CollectorCommit from the collector via the PowerShell AST and runs it in
# isolation (without running the collector), then checks the source invariants.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$collector = (Resolve-Path (Join-Path $PSScriptRoot '..\Invoke-VeridanCollection.ps1')).Path

$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw "parse errors: $(($parseErrors | ForEach-Object { $_.Message }) -join '; ')" }

function Assert-That([bool]$cond, [string]$msg) { if (-not $cond) { throw "FAIL: $msg" } }

# --- Get-CollectorCommit, extracted from the source and run in isolation ---
$fn = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CollectorCommit' }, $true) |
    Select-Object -First 1
Assert-That ($null -ne $fn) 'Get-CollectorCommit is defined'
. ([scriptblock]::Create($fn.Extent.Text))      # define it in this scope; it reads $script:COLLECTOR_COMMIT

$script:COLLECTOR_COMMIT = 'dev'
Assert-That ($null -eq (Get-CollectorCommit)) "'dev' yields `$null"

$real = '0123456789abcdef0123456789abcdef01234567'
$script:COLLECTOR_COMMIT = $real
Assert-That ((Get-CollectorCommit) -eq $real) '40 lowercase hex yields the commit'

$script:COLLECTOR_COMMIT = '0123456789abcdef0123456789abcdef0123456'   # 39 chars
Assert-That ($null -eq (Get-CollectorCommit)) '39 chars yields $null'

$script:COLLECTOR_COMMIT = '0123456789ABCDEF0123456789ABCDEF01234567'  # uppercase
Assert-That ($null -eq (Get-CollectorCommit)) 'uppercase yields $null'

# --- source invariants ---
$src = Get-Content -Raw -LiteralPath $collector
$needle = [regex]::Escape(("`$COLLECTOR_COMMIT = " + "'dev'"))
$devCount = ([regex]::Matches($src, $needle)).Count
Assert-That ($devCount -eq 1) "the line `$COLLECTOR_COMMIT = 'dev' appears exactly once (found $devCount)"

# --- collectorCommit stamped into both payloads, just after collectorVersion (index 2) ---
$inserts = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
    $n.Member.Value -eq 'Insert' -and $n.Extent.Text -match 'collectorCommit' }, $true)
Assert-That ($inserts.Count -ge 2) "collectorCommit is inserted in both payloads (found $($inserts.Count))"
$atIndex2 = ($inserts | Where-Object { $_.Arguments[0].Extent.Text -eq '2' }).Count
Assert-That ($atIndex2 -ge 2) 'collectorCommit is inserted at index 2 (just after collectorVersion) in both payloads'

$ccRefs = ([regex]::Matches($src, 'Get-CollectorCommit')).Count
Assert-That ($ccRefs -ge 3) "Get-CollectorCommit is defined and called in both payloads (found $ccRefs)"

# --- Free mode with a public client app: Get-VdnConnectParams builds the Connect-MgGraph splat ---
$cfn = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-VdnConnectParams' }, $true) |
    Select-Object -First 1
Assert-That ($null -ne $cfn) 'Get-VdnConnectParams is defined'
. ([scriptblock]::Create($cfn.Extent.Text))

function Assert-Throws([scriptblock]$sb, [string]$like, [string]$msg) {
    $thrown = $null
    try { & $sb } catch { $thrown = $_.Exception.Message }
    if ($null -eq $thrown) { throw "FAIL: $msg (nothing was thrown)" }
    if ($like -and $thrown -notlike $like) { throw "FAIL: $msg (got: $thrown)" }
}

# A stand-in for Connect-MgGraph with the real parameter names: splatting a key it does not have fails the bind.
$script:connectCalls = @()
function Connect-MgGraph {
    [CmdletBinding()]
    param([string] $TenantId, [string] $ClientId, [string] $CertificateThumbprint, [string[]] $Scopes,
          [string] $ContextScope, [switch] $NoWelcome)
    $script:connectCalls += , $PSBoundParameters
}
function Invoke-Connect($p) { $script:connectCalls = @(); Connect-MgGraph @p; $script:connectCalls[0] }

$scopes8  = @('Directory.Read.All', 'Policy.Read.All')
$tid      = '11111111-1111-4111-8111-111111111111'
$appA     = '22222222-2222-4222-8222-222222222222'
$appB     = '33333333-3333-4333-8333-333333333333'
$thumb    = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'

# Free, nothing given, no registered app: today's behaviour (Microsoft Graph Command Line Tools app: no -ClientId)
$c = Invoke-Connect (Get-VdnConnectParams -Mode Free -Scopes $scopes8 -ScanAppId '')
Assert-That (-not $c.ContainsKey('ClientId') -and -not $c.ContainsKey('TenantId') -and $c.ContainsKey('Scopes') -and $c.ContextScope -eq 'Process' -and $c.NoWelcome) 'Free, no ids: scopes + Process + NoWelcome only'
$c = Invoke-Connect (Get-VdnConnectParams -Mode Free -TenantId $tid -Scopes $scopes8 -ScanAppId '')
Assert-That ($c.TenantId -eq $tid -and -not $c.ContainsKey('ClientId')) 'Free with tenant: TenantId, no ClientId'

# Free with -ClientId: a public client, delegated and interactive
$c = Invoke-Connect (Get-VdnConnectParams -Mode Free -TenantId $tid -ClientId $appA -Scopes $scopes8 -ScanAppId '')
Assert-That ($c.ClientId -eq $appA -and $c.TenantId -eq $tid -and $c.ContextScope -eq 'Process' -and $c.NoWelcome -and ($c.Scopes -join ',') -eq ($scopes8 -join ',')) 'Free with -ClientId: ClientId + TenantId + Scopes + Process + NoWelcome'
Assert-That (-not $c.ContainsKey('CertificateThumbprint')) 'Free with -ClientId has no certificate'
$c = Invoke-Connect (Get-VdnConnectParams -Mode Free -ClientId $appA -Scopes $scopes8 -ScanAppId '')
Assert-That ($c.ClientId -eq $appA -and -not $c.ContainsKey('TenantId')) 'Free with -ClientId, no tenant: no TenantId'

# the built-in Veridan Scan app id: used in Free mode when no -ClientId, overridden by an explicit one
$c = Invoke-Connect (Get-VdnConnectParams -Mode Free -Scopes $scopes8 -ScanAppId $appB)
Assert-That ($c.ClientId -eq $appB) 'Free uses $VERIDAN_SCAN_APP_ID when no -ClientId was passed'
$c = Invoke-Connect (Get-VdnConnectParams -Mode Free -ClientId $appA -Scopes $scopes8 -ScanAppId $appB)
Assert-That ($c.ClientId -eq $appA) 'an explicit -ClientId wins over $VERIDAN_SCAN_APP_ID'

# a Free run never uses a certificate
Assert-Throws { Get-VdnConnectParams -Mode Free -CertificateThumbprint $thumb -Scopes $scopes8 -ScanAppId '' } '*Free*certificate*' 'Free + -CertificateThumbprint is refused'
Assert-Throws { Get-VdnConnectParams -Mode Free -ClientId $appA -CertificateThumbprint $thumb -Scopes $scopes8 -ScanAppId '' } '*Free*certificate*' 'Free + -ClientId + -CertificateThumbprint is refused'
Assert-Throws { Get-VdnConnectParams -Mode Free -ClientId 'not-a-guid' -Scopes $scopes8 -ScanAppId '' } '*-ClientId*GUID*' 'Free with a malformed -ClientId is refused'

# Full mode is unchanged: app-only, certificate, ignores the Veridan Scan app id
$c = Invoke-Connect (Get-VdnConnectParams -Mode Full -TenantId $tid -ClientId $appA -CertificateThumbprint $thumb -Scopes $scopes8 -ScanAppId $appB)
Assert-That ($c.TenantId -eq $tid -and $c.ClientId -eq $appA -and $c.CertificateThumbprint -eq $thumb -and $c.ContextScope -eq 'Process' -and $c.NoWelcome -and -not $c.ContainsKey('Scopes')) 'Full: TenantId, ClientId, CertificateThumbprint, Process, NoWelcome; no Scopes'
Assert-Throws { Get-VdnConnectParams -Mode Full -TenantId $tid -ClientId $appA -Scopes $scopes8 -ScanAppId '' } '*Full mode requires*' 'Full without a certificate is refused'
Assert-Throws { Get-VdnConnectParams -Mode Full -ClientId $appA -CertificateThumbprint $thumb -Scopes $scopes8 -ScanAppId '' } '*Full mode requires*' 'Full without a tenant is refused'
Assert-Throws { Get-VdnConnectParams -Mode Full -TenantId $tid -CertificateThumbprint $thumb -Scopes $scopes8 -ScanAppId $appB } '*Full mode requires*' 'Full never falls back to the Veridan Scan app id'

# --- the constant and the main block ---
Assert-That ([regex]::Matches($src, '(?m)^\$VERIDAN_SCAN_APP_ID = ''[^'']*''').Count -eq 1) '$VERIDAN_SCAN_APP_ID is defined once, near $COLLECTOR_VERSION'
Assert-That ($src -match "(?m)^\`$VERIDAN_SCAN_APP_ID = ''") '$VERIDAN_SCAN_APP_ID is empty until the app is registered'
$mainConnects = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Connect-MgGraph' }, $true)
Assert-That ($mainConnects.Count -eq 1 -and $mainConnects[0].Extent.Text -match '@') 'the main block has one Connect-MgGraph call, using the splat from Get-VdnConnectParams'
Assert-That ($src -match 'Get-VdnConnectParams\s+-Mode') 'the main block calls Get-VdnConnectParams'

Write-Host 'Collector.Tests.ps1: OK'
exit 0

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

Write-Host 'Collector.Tests.ps1: OK'
exit 0

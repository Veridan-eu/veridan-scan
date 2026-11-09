# tests/Release.Tests.ps1 - tools/release.ps1 (spec rev 3, section 12 step 2).
# Each case builds a throwaway repo in TEMP (work tree + bare origin, a commit, a tag) and runs
# the real release.ps1 against it. Nothing here touches a real tenant or the real origin.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot      = Split-Path -Parent $PSScriptRoot
$realCollector = Join-Path $repoRoot 'Invoke-VeridanCollection.ps1'
$realRelease   = Join-Path $repoRoot 'tools\release.ps1'

function Assert-That([bool] $cond, [string] $msg) { if (-not $cond) { throw "FAIL: $msg" } }

# Run git with stderr discarded (its LF/CRLF and info lines must not become terminating errors
# under ErrorActionPreference Stop) and fail only on a non-zero exit code.
function Git-Do {
    $out = & git @args 2>$null
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed (exit $LASTEXITCODE)" }
    $out
}

function New-Lab {
    param([switch] $Bom)
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('rel-' + [Guid]::NewGuid().ToString('N'))
    $work = Join-Path $root 'work'
    $bare = Join-Path $root 'origin.git'
    New-Item -ItemType Directory -Force -Path (Join-Path $work 'tools') | Out-Null
    $bytes = [System.IO.File]::ReadAllBytes($realCollector)
    if ($Bom) { $bytes = [byte[]]@(0xEF, 0xBB, 0xBF) + $bytes }
    [System.IO.File]::WriteAllBytes((Join-Path $work 'Invoke-VeridanCollection.ps1'), $bytes)
    Copy-Item -LiteralPath $realRelease -Destination (Join-Path $work 'tools\release.ps1')
    Set-Content -LiteralPath (Join-Path $work '.gitignore') -Value 'dist/'   # mirror the repo: dist/ is ignored
    Push-Location $work
    try {
        Git-Do init -q | Out-Null
        Git-Do config core.autocrlf false | Out-Null       # the collector is LF; no CRLF rewrite, no warning
        Git-Do config core.safecrlf false | Out-Null
        Git-Do config user.email 'test@veridan.local' | Out-Null
        Git-Do config user.name  'test' | Out-Null
        Git-Do checkout -q -b main | Out-Null
        Git-Do add -A | Out-Null
        Git-Do commit -q -m init | Out-Null
        Git-Do init -q --bare $bare | Out-Null
        Git-Do remote add origin $bare | Out-Null
        Git-Do push -q origin main | Out-Null
    } finally { Pop-Location }
    [pscustomobject]@{ Root = $root; Work = $work }
}

function Add-Tag($work, $tag) {
    Push-Location $work
    try { Git-Do tag $tag | Out-Null; Git-Do push -q origin $tag | Out-Null } finally { Pop-Location }
}

function Invoke-Release($work, $version) {
    $rel = Join-Path $work 'tools\release.ps1'
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $rel -Version $version 2>&1
    [pscustomobject]@{ Code = $LASTEXITCODE; Out = ($out | Out-String) }
}

$labs = @()
try {
    # --- success ---
    $lab = New-Lab; $labs += $lab.Root
    Add-Tag $lab.Work 'v0.9.0'
    $r = Invoke-Release $lab.Work '0.9.0'
    Assert-That ($r.Code -eq 0) "success exits 0 (got $($r.Code): $($r.Out))"
    $distFile = Join-Path $lab.Work 'dist\Invoke-VeridanCollection.ps1'
    Assert-That (Test-Path -LiteralPath $distFile) 'dist collector written'
    $head = ((Git-Do -C $lab.Work rev-parse HEAD) | Out-String).Trim()
    $srcText = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes((Join-Path $lab.Work 'Invoke-VeridanCollection.ps1')))
    $dstText = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($distFile))
    $expected = $srcText.Replace("`$COLLECTOR_COMMIT = 'dev'", "`$COLLECTOR_COMMIT = '$head'")
    Assert-That ($dstText -ceq $expected) 'only the collectorCommit line changed'
    $realHash = (Get-FileHash -LiteralPath $distFile -Algorithm SHA256).Hash.ToLower()
    $sums = (Get-Content -LiteralPath (Join-Path $lab.Work 'dist\SHA256SUMS') -Raw)
    Assert-That ($sums.Trim() -eq "$realHash  Invoke-VeridanCollection.ps1") 'SHA256SUMS line correct'
    Assert-That ($r.Out -match 'gh release create v0.9.0') 'prints the gh command'
    Assert-That ($r.Out -notmatch '(?m)^gh ') 'does not run gh itself'

    # --- second run: byte-identical dist ---
    $b1 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($distFile))
    $r2 = Invoke-Release $lab.Work '0.9.0'
    Assert-That ($r2.Code -eq 0) 'second run exits 0'
    $b2 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($distFile))
    Assert-That ($b1 -eq $b2) 'second run is byte-identical'

    # --- BOM preserved ---
    $labB = New-Lab -Bom; $labs += $labB.Root
    Add-Tag $labB.Work 'v0.9.0'
    $rb = Invoke-Release $labB.Work '0.9.0'
    Assert-That ($rb.Code -eq 0) "BOM lab exits 0 (got $($rb.Code): $($rb.Out))"
    $distB = [System.IO.File]::ReadAllBytes((Join-Path $labB.Work 'dist\Invoke-VeridanCollection.ps1'))
    Assert-That ($distB[0] -eq 0xEF -and $distB[1] -eq 0xBB -and $distB[2] -eq 0xBF) 'BOM preserved'

    # --- refusals: each separately, exit 2, dist/ not created ---
    $l1 = New-Lab; $labs += $l1.Root; Add-Tag $l1.Work 'v0.9.0'
    Add-Content -LiteralPath (Join-Path $l1.Work 'Invoke-VeridanCollection.ps1') -Value '# dirty'
    $x = Invoke-Release $l1.Work '0.9.0'
    Assert-That ($x.Code -eq 2 -and $x.Out -match 'REFUSED') 'refuse on uncommitted changes'
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $l1.Work 'dist'))) 'no dist/ on refusal (dirty)'

    $l2 = New-Lab; $labs += $l2.Root            # no tag
    $x = Invoke-Release $l2.Work '0.9.0'
    Assert-That ($x.Code -eq 2 -and $x.Out -match 'REFUSED') 'refuse on missing tag'
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $l2.Work 'dist'))) 'no dist/ on refusal (tag)'

    $l3 = New-Lab; $labs += $l3.Root; Add-Tag $l3.Work 'v0.9.1'   # file is 0.9.0
    $x = Invoke-Release $l3.Work '0.9.1'
    Assert-That ($x.Code -eq 2 -and $x.Out -match 'REFUSED') 'refuse on version mismatch'

    $l4 = New-Lab; $labs += $l4.Root; Add-Tag $l4.Work 'v0.9.0'   # commit after tag/push
    Push-Location $l4.Work
    try { Set-Content -LiteralPath 'extra.txt' -Value 'x'; Git-Do add -A | Out-Null; Git-Do commit -q -m more | Out-Null } finally { Pop-Location }
    $x = Invoke-Release $l4.Work '0.9.0'
    Assert-That ($x.Code -eq 2 -and $x.Out -match 'REFUSED') 'refuse when HEAD is ahead of origin/main'

    # --- remote tag points to a different commit than HEAD (Fable) ---
    # HEAD == origin/main == B, local tag v0.9.0 == B, but origin's tag is force-moved to A.
    # Every earlier check passes; only the remote-tag-SHA comparison must catch it.
    $l5 = New-Lab; $labs += $l5.Root
    Push-Location $l5.Work
    try {
        $shaA = ((Git-Do rev-parse HEAD) | Out-String).Trim()               # init commit, already on origin
        Set-Content -LiteralPath 'more.txt' -Value 'y'
        Git-Do add -A | Out-Null
        Git-Do commit -q -m second | Out-Null
        Git-Do push -q origin main | Out-Null                               # HEAD == origin/main == B
        Git-Do tag v0.9.0 | Out-Null                                        # local tag at B (HEAD)
        Git-Do push -q origin v0.9.0 | Out-Null                             # origin tag at B
        Git-Do push -q --force origin "${shaA}:refs/tags/v0.9.0" | Out-Null # origin tag force-moved to A
    } finally { Pop-Location }
    $x = Invoke-Release $l5.Work '0.9.0'
    Assert-That ($x.Code -eq 2 -and $x.Out -match 'REFUSED') 'refuse when origin tag points elsewhere'
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $l5.Work 'dist'))) 'no dist/ on refusal (remote tag SHA)'

    Write-Host 'Release.Tests.ps1: OK'
    exit 0
}
finally {
    foreach ($d in $labs) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
}

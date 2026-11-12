# tools/release.ps1 - stamp collectorCommit into a dist/ copy and write SHA256SUMS.
# Publishing is a person's step: this script PRINTS the gh command, it never runs it.
# No new Graph scopes, nothing against a tenant.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $Version)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Deny([string] $Message) {
    Write-Host "REFUSED: $Message"
    exit 2
}

# Validate -Version in the body (a REFUSED/exit 2, the contract) rather than with [ValidatePattern],
# whose binding failure is a bare exit 1. \z (absolute end, no trailing newline) not $.
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\z') { Deny "Version '$Version' is not x.y.z" }

$repo      = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $repo 'Invoke-VeridanCollection.ps1'
$tag       = "v$Version"

if (-not (Test-Path -LiteralPath $collector)) { Deny "collector not found at $collector" }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Deny 'git was not found on PATH' }

# Run a read-only git command in the repo. stderr is discarded and ErrorActionPreference is
# Continue inside this function (function-scoped, so the caller keeps Stop) so a git warning on
# stderr cannot stop the script with a bare exit 1 under Windows PowerShell 5.1; a non-zero exit
# becomes a REFUSED, per the contract. Returns stdout as one string.
function Invoke-Git {
    $ErrorActionPreference = 'Continue'
    $out = & git -C $repo @args 2>$null
    if ($LASTEXITCODE -ne 0) { Deny "git $($args -join ' ') failed (exit $LASTEXITCODE)" }
    ($out | Out-String)
}

# --- git state (read-only checks; dist/ is written only if all pass) ---
$status = (Invoke-Git status --porcelain).Trim()
if ($status) { Deny 'the working tree has uncommitted changes' }

Invoke-Git fetch -q origin | Out-Null
$head = (Invoke-Git rev-parse HEAD).Trim()
$originMain = (Invoke-Git rev-parse origin/main).Trim()
if ($head -ne $originMain) { Deny "HEAD ($head) is not origin/main ($originMain)" }

$localTag = (Invoke-Git tag --list $tag).Trim()
if (-not $localTag) { Deny "tag $tag does not exist locally" }
$tagCommit = (Invoke-Git rev-list -n 1 $tag).Trim()
if ($tagCommit -ne $head) { Deny "tag $tag does not point to HEAD" }

# The tag on origin must exist AND point to HEAD, not merely exist. Query both the tag ref and
# its peeled form: 'ls-remote --tags origin <tag>' with a pattern returns only '<sha>\trefs/tags/<tag>'
# (for an annotated tag that is the tag object, not the commit), so the peeled commit line
# '<commit>\trefs/tags/<tag>^{}' must be requested explicitly. ls-remote matches on the ref tail,
# so a stray ref like refs/heads/refs/tags/<tag> can also come back; compare each line's ref field
# EXACTLY (not by suffix). Prefer the peeled '^{}' line (the commit an annotated tag points to);
# a lightweight tag has no peeled line and its plain line is the commit.
$remoteLines = (Invoke-Git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}") -split "`r?`n" | Where-Object { $_.Trim() }
$plainSha = $null
$peelSha  = $null
foreach ($line in $remoteLines) {
    $sha, $ref = $line -split "`t", 2
    if     ($ref -ceq "refs/tags/$tag^{}") { $peelSha  = $sha.Trim() }
    elseif ($ref -ceq "refs/tags/$tag")    { $plainSha = $sha.Trim() }
}
$remoteSha = if ($peelSha) { $peelSha } else { $plainSha }
if (-not $remoteSha) { Deny "tag $tag is not on origin" }
if ($remoteSha -ne $head) { Deny "tag $tag on origin points to $remoteSha, not HEAD ($head)" }

# Read the bytes once - these exact bytes are what we splice and write. Their git blob hash must
# equal the committed blob, so a local .git/info/attributes or a smudge filter that rewrote the
# working tree becomes a REFUSED rather than a silently re-encoded release (.gitattributes '* -text'
# keeps them equal normally). Hashing $bytes (not a second git read of the file) closes the gap
# between what is verified and what is written. A git blob hash is SHA1 of "blob <len>\0" + content;
# this assumes the repo's default SHA-1 object format. A SHA-256 object-format repo would produce a
# different `rev-parse HEAD:...` hash and be refused here - correctly, since release is SHA-1 only.
$bytes = [System.IO.File]::ReadAllBytes($collector)
$blobHeader = [System.Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
$buf = New-Object 'byte[]' ($blobHeader.Length + $bytes.Length)
[Array]::Copy($blobHeader, 0, $buf, 0, $blobHeader.Length)
[Array]::Copy($bytes, 0, $buf, $blobHeader.Length, $bytes.Length)
$sha1 = [System.Security.Cryptography.SHA1]::Create()
try { $wtHash = (($sha1.ComputeHash($buf) | ForEach-Object { $_.ToString('x2') }) -join '') }
finally { $sha1.Dispose() }
$blobHash = (Invoke-Git rev-parse "HEAD:Invoke-VeridanCollection.ps1").Trim()
if ($wtHash -ne $blobHash) { Deny 'the working-tree collector differs from its committed blob (check .gitattributes / smudge filters)' }

# --- file checks (text view is only for matching; the bytes are what we write) ---
$text  = [System.Text.Encoding]::UTF8.GetString($bytes)

$vMatch = [regex]::Match($text, '(?m)^\$COLLECTOR_VERSION = ''([^'']*)''')
if (-not $vMatch.Success) { Deny 'cannot find $COLLECTOR_VERSION in the collector' }
if ($vMatch.Groups[1].Value -ne $Version) { Deny "`$COLLECTOR_VERSION is $($vMatch.Groups[1].Value), not $Version" }

$devNeedle = "`$COLLECTOR_COMMIT = 'dev'"
$devCount = ([regex]::Matches($text, [regex]::Escape($devNeedle))).Count
if ($devCount -ne 1) { Deny "the line `$COLLECTOR_COMMIT = 'dev' occurs $devCount time(s), not once" }

# --- byte-exact stamp: replace only the dev needle; every other byte (encoding, BOM, CRLF) stays ---
$searchBytes  = [System.Text.Encoding]::ASCII.GetBytes($devNeedle)
$replaceBytes = [System.Text.Encoding]::ASCII.GetBytes("`$COLLECTOR_COMMIT = '$head'")

$idx = -1
$limit = $bytes.Length - $searchBytes.Length
for ($i = 0; $i -le $limit -and $idx -lt 0; $i++) {
    $match = $true
    for ($j = 0; $j -lt $searchBytes.Length; $j++) {
        if ($bytes[$i + $j] -ne $searchBytes[$j]) { $match = $false; break }
    }
    if ($match) { $idx = $i }
}
if ($idx -lt 0) { Deny 'the $COLLECTOR_COMMIT dev bytes were not found' }

$out = New-Object 'byte[]' ($bytes.Length - $searchBytes.Length + $replaceBytes.Length)
[Array]::Copy($bytes, 0, $out, 0, $idx)
[Array]::Copy($replaceBytes, 0, $out, $idx, $replaceBytes.Length)
[Array]::Copy($bytes, $idx + $searchBytes.Length, $out, $idx + $replaceBytes.Length, $bytes.Length - $idx - $searchBytes.Length)

# --- write dist/ (only now) ---
$dist = Join-Path $repo 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$distCollector = Join-Path $dist 'Invoke-VeridanCollection.ps1'
[System.IO.File]::WriteAllBytes($distCollector, $out)

$sha  = (Get-FileHash -LiteralPath $distCollector -Algorithm SHA256).Hash.ToLower()
$sums = "$sha  Invoke-VeridanCollection.ps1`n"
[System.IO.File]::WriteAllBytes((Join-Path $dist 'SHA256SUMS'), [System.Text.Encoding]::ASCII.GetBytes($sums))

Write-Host "dist\Invoke-VeridanCollection.ps1 stamped with $head"
Write-Host "dist\SHA256SUMS: $sha"
Write-Host ''
Write-Host 'Publish it yourself after reviewing dist\ (this script does not publish):'
Write-Host "  gh release create $tag dist/Invoke-VeridanCollection.ps1 dist/SHA256SUMS --title ""veridan-scan $tag"" --notes ""$sha"""
exit 0

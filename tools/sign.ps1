
# tools/sign.ps1 - Authenticode-sign PowerShell files of a release (dist\ only, by default).
#
# Production path: Azure Artifact Signing (formerly Trusted Signing) through SignTool and the Artifact
# Signing dlib. The command is exactly
#   signtool sign /v /debug /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256
#                 /dlib <Azure.CodeSigning.Dlib.dll> /dmdf <metadata.json> <file>
# The sign-in is the operator's own `az login` (the dlib uses DefaultAzureCredential). This script never
# asks for, reads, passes on or stores a credential, and never signs in to anything itself.
#
# Test path: -TestCertificateThumbprint <thumb> signs with Set-AuthenticodeSignature and a certificate from
# Cert:\CurrentUser\My, with a timestamp server only when -TimestampServer is given. It exists so the signing
# pipeline can be tested offline, without Azure. A self-signed certificate is not trusted by anyone: never
# publish a file signed this way.
#
# After signing EVERY file the signature is read back (Get-AuthenticodeSignature) and checked:
#   production: Status Valid, a timestamp (TimeStamperCertificate), and a signer subject that contains
#               -ExpectedSubject (default 'O=Intelligence EOOD': an exact RDN of the signer subject, key and
#               value compared whole, not a substring; it must equal the validated legal name in the
#               Artifact Signing certificate profile);
#   test:       Status Valid or UnknownError (untrusted self-signed root) and a signer thumbprint equal to
#               -TestCertificateThumbprint.
# Anything else is REFUSED, exit 2, naming the file. Same contract as tools/release.ps1.
#
# A .ps1 with non-ASCII bytes and no UTF-8 BOM is refused (its signature would depend on the ANSI code page).
#
# Guard: files outside the repository's dist\ folder are refused unless -AllowOutsideDist is passed, so the
# wrong thing cannot be signed by a typo. Every path is checked before the first file is signed.
#
# Nothing here touches a Microsoft 365 / Entra tenant. SignTool and the dlib are not installed or downloaded
# by this script; if one is missing it prints how to get it.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]] $Path,

    # JSON for the dlib: Endpoint, CodeSigningAccountName, CertificateProfileName (see signing-metadata.example.json).
    [string] $MetadataPath,
    [string] $SignToolPath,
    [string] $DlibPath,

    # Test path (no Azure): thumbprint of a code-signing certificate in Cert:\CurrentUser\My.
    [string] $TestCertificateThumbprint,
    [string] $TimestampServer,

    [string] $ExpectedSubject = 'O=Intelligence EOOD',
    [switch] $AllowOutsideDist
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Deny([string] $Message) { throw [System.InvalidOperationException]::new($Message) }

function Get-VsgSignToolPath {
    # signtool.exe from the Windows SDK, newest SDK version first (a numeric sort: 10.0.9.0 < 10.0.26100.0).
    param([string] $Root = 'C:\Program Files (x86)\Windows Kits\10\bin')
    if (-not (Test-Path -LiteralPath $Root)) { return $null }
    $cands = foreach ($d in Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue) {
        $exe = Join-Path $d.FullName 'x64\signtool.exe'
        $ver = $null
        if ((Test-Path -LiteralPath $exe) -and [version]::TryParse($d.Name, [ref]$ver)) {
            [pscustomobject]@{ Version = $ver; Path = $exe }
        }
    }
    $best = @($cands | Sort-Object -Property Version -Descending) | Select-Object -First 1
    if ($best) { return $best.Path } else { return $null }
}

function Get-VsgInstallHint {
    return @(
        'Install the Artifact Signing tools yourself (this script downloads nothing):',
        '  1. Windows SDK signing tools (signtool.exe), e.g. "Windows SDK Signing Tools for Desktop Apps"; they land in',
        '     C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe (found automatically, or pass -SignToolPath).',
        '  2. The NuGet package Microsoft.ArtifactSigning.Client (older name: Microsoft.Trusted.Signing.Client), extracted',
        '     (a .nupkg is a zip file). The dlib is bin\x64\Azure.CodeSigning.Dlib.dll inside it.',
        '     Pass it with -DlibPath, or set the environment variable VERIDAN_SIGNING_DLIB to its full path.'
    ) -join "`n"
}

function Get-VsgSignToolArguments {
    param([string] $DlibPath, [string] $MetadataPath, [string] $File)
    return @('sign', '/v', '/debug', '/fd', 'SHA256', '/tr', 'http://timestamp.acs.microsoft.com', '/td', 'SHA256',
             '/dlib', $DlibPath, '/dmdf', $MetadataPath, $File)
}

function Test-VsgInsideDist {
    param([string] $File, [string] $Dist)
    $f = [System.IO.Path]::GetFullPath($File)
    $d = [System.IO.Path]::GetFullPath($Dist).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    return $f.StartsWith($d, [System.StringComparison]::OrdinalIgnoreCase)
}

function Read-VsgMetadata {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { Deny "metadata file not found: $Path (see tools\signing-metadata.example.json)" }
    try { $m = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { Deny "metadata file $Path is not valid JSON" }
    foreach ($name in 'Endpoint', 'CodeSigningAccountName', 'CertificateProfileName') {
        $p = if ($m) { $m.PSObject.Properties[$name] } else { $null }
        if (-not $p -or [string]::IsNullOrWhiteSpace("$($p.Value)")) { Deny "metadata file $Path has no value for $name" }
    }
    return $m
}

function Assert-VsgSignature {
    # Throws (REFUSED text, naming the file) unless the signature is what a release needs.
    param($Signature, [string] $File, [string] $ExpectedSubject, [string] $TestCertificateThumbprint)
    if ($null -eq $Signature -or $null -eq $Signature.SignerCertificate) { Deny "$File has no signer certificate after signing (Status $(if ($Signature) { $Signature.Status } else { 'unknown' }))" }
    $status = "$($Signature.Status)"
    if ($TestCertificateThumbprint) {
        if ($status -notin 'Valid', 'UnknownError') { Deny "$File : Status is $status (test mode accepts Valid or UnknownError)" }
        if ($Signature.SignerCertificate.Thumbprint -ne $TestCertificateThumbprint) {
            Deny "$File : signer thumbprint $($Signature.SignerCertificate.Thumbprint) is not the test certificate $TestCertificateThumbprint"
        }
        return
    }
    if ($status -ne 'Valid') { Deny "$File : Status is $status, not Valid" }
    if ($null -eq $Signature.TimeStamperCertificate) { Deny "$File : the signature carries no timestamp" }
    if (-not (Test-VsgSubject -Subject $Signature.SignerCertificate.Subject -Expected $ExpectedSubject)) {
        Deny "$File : signer '$($Signature.SignerCertificate.Subject)' does not have the exact name part '$ExpectedSubject'"
    }
}

function Split-VsgDn {
    # A distinguished name -> list of @{ Key; Value } (one per RDN). Commas inside "quotes" or after a backslash
    # do not split; quotes are removed. Enough for certificate subjects like: CN=Name, O="Org, Ltd", C=BG.
    param([string] $Dn)
    $parts = New-Object System.Collections.ArrayList
    $sb = New-Object System.Text.StringBuilder
    $inQuote = $false; $esc = $false
    foreach ($ch in $Dn.ToCharArray()) {
        if ($esc) { [void]$sb.Append($ch); $esc = $false; continue }
        if ($ch -eq '\') { $esc = $true; continue }
        if ($ch -eq '"') { $inQuote = -not $inQuote; continue }
        if ($ch -eq ',' -and -not $inQuote) { [void]$parts.Add($sb.ToString()); [void]$sb.Clear(); continue }
        [void]$sb.Append($ch)
    }
    [void]$parts.Add($sb.ToString())
    foreach ($p in $parts) {
        $i = $p.IndexOf('=')
        if ($i -gt 0) { [pscustomobject]@{ Key = $p.Substring(0, $i).Trim(); Value = $p.Substring($i + 1).Trim() } }
    }
}

function Test-VsgSubject {
    # Every RDN of -Expected (e.g. 'O=Intelligence EOOD') must equal an RDN of the signer subject: key and value
    # compared whole, case-insensitively. 'O=Intelligence EOOD Holding' or 'CN=O=Intelligence EOOD' do not match.
    param([string] $Subject, [string] $Expected)
    $have = @(Split-VsgDn -Dn $Subject)
    $want = @(Split-VsgDn -Dn $Expected)
    if ($want.Count -eq 0) { return $false }
    foreach ($w in $want) {
        $hit = @($have | Where-Object { $_.Key -ieq $w.Key -and $_.Value -ieq $w.Value })
        if ($hit.Count -eq 0) { return $false }
    }
    return $true
}

function Assert-VsgEncodingSafe {
    # Authenticode hashes a .ps1 that has no BOM in the machine's ANSI code page, so a non-ASCII byte without a
    # UTF-8 BOM can give HashMismatch on another machine (1251 vs 1252). Refuse such a file; fix it before signing.
    param([string] $File)
    if ([System.IO.Path]::GetExtension($File) -notin '.ps1', '.psm1', '.psd1') { return }
    $b = [System.IO.File]::ReadAllBytes($File)
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return }
    foreach ($x in $b) {
        if ($x -gt 127) { Deny "$File contains non-ASCII bytes and has no UTF-8 BOM: its signature could fail on other machines (ANSI code page). Make it pure ASCII, or add a BOM." }
    }
}

# ==================================================================== main
if ($MyInvocation.InvocationName -eq '.') { return }    # dot-sourced: functions only

try {
    $repo = Split-Path -Parent $PSScriptRoot
    $dist = Join-Path $repo 'dist'

    # --- every path checked before the first file is signed ---
    $files = @()
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { Deny "file not found: $p" }
        $full = (Resolve-Path -LiteralPath $p).ProviderPath
        if (-not $AllowOutsideDist -and -not (Test-VsgInsideDist -File $full -Dist $dist)) {
            Deny "$full is outside $dist (pass -AllowOutsideDist if you really mean to sign it)"
        }
        Assert-VsgEncodingSafe -File $full
        $files += $full
    }

    if ($TestCertificateThumbprint) {
        $certPath = "Cert:\CurrentUser\My\$TestCertificateThumbprint"
        if (-not (Test-Path -LiteralPath $certPath)) { Deny "test certificate $TestCertificateThumbprint is not in Cert:\CurrentUser\My" }
        $cert = Get-Item -LiteralPath $certPath
        Write-Host 'TEST signing with a certificate from Cert:\CurrentUser\My - not for publication.' -ForegroundColor Yellow
    } else {
        if (-not $MetadataPath) { Deny 'production signing needs -MetadataPath (copy tools\signing-metadata.example.json and check it)' }
        $null = Read-VsgMetadata -Path $MetadataPath
        $metadataFull = (Resolve-Path -LiteralPath $MetadataPath).ProviderPath

        $signtool = $SignToolPath
        if (-not $signtool) { $signtool = Get-VsgSignToolPath }
        if (-not $signtool -or -not (Test-Path -LiteralPath $signtool)) { Deny "signtool.exe was not found.`n$(Get-VsgInstallHint)" }

        $dlib = $DlibPath
        if (-not $dlib) { $dlib = $env:VERIDAN_SIGNING_DLIB }
        if (-not $dlib -or -not (Test-Path -LiteralPath $dlib)) { Deny "Azure.CodeSigning.Dlib.dll was not found.`n$(Get-VsgInstallHint)" }
        $dlibFull = (Resolve-Path -LiteralPath $dlib).ProviderPath
        Write-Host 'Signing through Azure Artifact Signing; sign in first with: az login' -ForegroundColor Cyan
    }

    foreach ($f in $files) {
        if ($TestCertificateThumbprint) {
            $sp = @{ FilePath = $f; Certificate = $cert; HashAlgorithm = 'SHA256' }
            if ($TimestampServer) { $sp.TimestampServer = $TimestampServer }
            $null = Set-AuthenticodeSignature @sp
        } else {
            & $signtool @(Get-VsgSignToolArguments -DlibPath $dlibFull -MetadataPath $metadataFull -File $f)
            if ($LASTEXITCODE -ne 0) { Deny "signtool failed on $f (exit $LASTEXITCODE)" }
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $f
        Assert-VsgSignature -Signature $sig -File $f -ExpectedSubject $ExpectedSubject -TestCertificateThumbprint $TestCertificateThumbprint
        Write-Host "signed: $f ($($sig.Status), $($sig.SignerCertificate.Subject))"
    }
    exit 0
}
catch {
    Write-Host "REFUSED: $($_.Exception.Message)"
    exit 2
}

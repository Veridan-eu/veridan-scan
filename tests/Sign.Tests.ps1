
# tests/Sign.Tests.ps1 - tools/sign.ps1 (release signing through Azure Artifact Signing).
# Two layers. (1) The script's functions are extracted via the PowerShell AST and run in isolation against
# fakes (a fake signtool folder, fake signature objects). (2) The real script runs as a child process in a
# throwaway lab repo: the TEST path signs with a self-signed code-signing certificate that this test creates in
# Cert:\CurrentUser\My and removes again; the PRODUCTION path runs against a fake signtool (a .cmd file) that
# records its arguments. Nothing here signs in, reaches Azure, a timestamp server or any tenant.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot  = Split-Path -Parent $PSScriptRoot
$realSign  = Join-Path $repoRoot 'tools\sign.ps1'

function Assert-That([bool] $cond, [string] $msg) { if (-not $cond) { throw "FAIL: $msg" } }
function Assert-Throws([scriptblock] $sb, [string] $like, [string] $msg) {
    $thrown = $null
    try { & $sb } catch { $thrown = $_.Exception.Message }
    if ($null -eq $thrown) { throw "FAIL: $msg (nothing was thrown)" }
    if ($like -and $thrown -notlike $like) { throw "FAIL: $msg (got: $thrown)" }
}

Assert-That (Test-Path -LiteralPath $realSign) 'tools\sign.ps1 exists'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($realSign, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw "parse errors: $(($parseErrors | ForEach-Object { $_.Message }) -join '; ')" }
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('sign-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
$testCert = $null
try {
    # --- 1. signtool discovery: newest version first (numeric, not alphabetical) ---
    $kits = Join-Path $tmpRoot 'kits\bin'
    foreach ($v in '10.0.19041.0', '10.0.9.0', '10.0.26100.0') {
        New-Item -ItemType Directory -Force -Path (Join-Path $kits "$v\x64") | Out-Null
        Set-Content -LiteralPath (Join-Path $kits "$v\x64\signtool.exe") -Value 'x'
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $kits '10.0.30000.0\x86') | Out-Null   # no x64\signtool.exe: ignored
    $found = Get-VsgSignToolPath -Root $kits
    Assert-That ($found -like '*10.0.26100.0*x64*signtool.exe') "newest signtool wins (got $found)"
    Assert-That ($null -eq (Get-VsgSignToolPath -Root (Join-Path $tmpRoot 'nokits'))) 'no Windows SDK -> $null'

    # --- 2. the signtool command line is exactly the documented Artifact Signing one ---
    $a = @(Get-VsgSignToolArguments -DlibPath 'C:\d\Azure.CodeSigning.Dlib.dll' -MetadataPath 'C:\m\metadata.json' -File 'C:\r\dist\x.ps1')
    $expected = @('sign', '/v', '/debug', '/fd', 'SHA256', '/tr', 'http://timestamp.acs.microsoft.com', '/td', 'SHA256',
                  '/dlib', 'C:\d\Azure.CodeSigning.Dlib.dll', '/dmdf', 'C:\m\metadata.json', 'C:\r\dist\x.ps1')
    Assert-That (($a -join '|') -ceq ($expected -join '|')) "signtool arguments (got: $($a -join ' '))"

    # --- 3. dist guard ---
    $dist = Join-Path $tmpRoot 'repo\dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    Set-Content -LiteralPath (Join-Path $dist 'a.ps1') -Value 'a'
    Set-Content -LiteralPath (Join-Path $tmpRoot 'repo\b.ps1') -Value 'b'
    New-Item -ItemType Directory -Force -Path (Join-Path $tmpRoot 'repo\dist-evil') | Out-Null
    Set-Content -LiteralPath (Join-Path $tmpRoot 'repo\dist-evil\c.ps1') -Value 'c'
    Assert-That (Test-VsgInsideDist -File (Join-Path $dist 'a.ps1') -Dist $dist) 'file in dist\ is inside'
    Assert-That (-not (Test-VsgInsideDist -File (Join-Path $tmpRoot 'repo\b.ps1') -Dist $dist)) 'file next to dist\ is outside'
    Assert-That (-not (Test-VsgInsideDist -File (Join-Path $tmpRoot 'repo\dist-evil\c.ps1') -Dist $dist)) 'dist-evil\ is not dist\'
    Assert-That (-not (Test-VsgInsideDist -File (Join-Path $dist '..\b.ps1') -Dist $dist)) 'dist\..\ is outside'

    # --- 4. metadata ---
    $good = Join-Path $tmpRoot 'm-good.json'
    Set-Content -LiteralPath $good -Value '{"Endpoint":"https://neu.codesigning.azure.net","CodeSigningAccountName":"veridansigning","CertificateProfileName":"veridan-public"}'
    $m = Read-VsgMetadata -Path $good
    Assert-That ($m.CodeSigningAccountName -eq 'veridansigning') 'metadata read'
    $bad = Join-Path $tmpRoot 'm-bad.json'
    Set-Content -LiteralPath $bad -Value '{"Endpoint":"https://neu.codesigning.azure.net","CodeSigningAccountName":""}'
    Assert-Throws { Read-VsgMetadata -Path $bad } '*CodeSigningAccountName*' 'metadata with an empty field is refused (names the field)'
    Set-Content -LiteralPath $bad -Value '{"Endpoint":"https://neu.codesigning.azure.net","CodeSigningAccountName":"veridansigning"}'
    Assert-Throws { Read-VsgMetadata -Path $bad } '*CertificateProfileName*' 'metadata missing a field is refused (names the field)'
    Set-Content -LiteralPath $bad -Value 'not json'
    Assert-Throws { Read-VsgMetadata -Path $bad } '*not valid JSON*' 'metadata that is not JSON is refused'
    Assert-Throws { Read-VsgMetadata -Path (Join-Path $tmpRoot 'nope.json') } '*not found*' 'missing metadata file is refused'

    # --- 5. signature verification, on fake signature objects ---
    function New-FakeSig($status, $subject, $thumb, [bool] $stamped) {
        $signer = if ($subject) { [pscustomobject]@{ Subject = $subject; Thumbprint = $thumb } } else { $null }
        $ts = if ($stamped) { [pscustomobject]@{ Subject = 'CN=ts' } } else { $null }
        [pscustomobject]@{ Status = $status; SignerCertificate = $signer; TimeStamperCertificate = $ts }
    }
    $subj = 'CN=Intelligence EOOD, O=Intelligence EOOD, C=BG'
    Assert-VsgSignature -Signature (New-FakeSig 'Valid' $subj 'AA' $true) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'NotSigned' $null $null $false) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD' } '*f.ps1*' 'unsigned is refused, names the file'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'Valid' $subj 'AA' $false) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD' } '*timestamp*' 'production without timestamp is refused'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'UnknownError' $subj 'AA' $true) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD' } '*Status*' 'production needs Status Valid'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'Valid' 'CN=Someone Else, O=Other Ltd' 'AA' $true) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD' } '*O=Intelligence EOOD*' 'production with the wrong signer is refused'
    # the O= RDN is compared whole, not as a substring
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'Valid' 'CN=Intelligence EOOD, O=Intelligence EOOD Holding, C=BG' 'AA' $true) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD' } '*exact*' 'a longer O= value is refused'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'Valid' 'CN=O=Intelligence EOOD, O=Other Ltd' 'AA' $true) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD' } '*exact*' 'the text inside another RDN is refused'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'Valid' 'CN=x, OU=Intelligence EOOD' 'AA' $true) -File 'f.ps1' -ExpectedSubject 'O=Intelligence EOOD' } '*exact*' 'OU= is not O='
    Assert-That (Test-VsgSubject -Subject 'CN=x, o="Intelligence EOOD", C=BG' -Expected 'O=Intelligence EOOD') 'quoted value and lower-case key match'
    Assert-That (Test-VsgSubject -Subject 'CN=x, O="Org, Ltd", C=BG' -Expected 'O="Org, Ltd"') 'a comma inside quotes does not split'
    Assert-That (-not (Test-VsgSubject -Subject 'CN=x, O=Intelligence EOOD' -Expected '')) 'an empty expectation matches nothing'
    # test mode: UnknownError (untrusted self-signed root) accepted, thumbprint must match, no timestamp needed
    Assert-VsgSignature -Signature (New-FakeSig 'UnknownError' 'CN=t' 'ABCD' $false) -File 'f.ps1' -ExpectedSubject 'x' -TestCertificateThumbprint 'abcd'
    Assert-VsgSignature -Signature (New-FakeSig 'Valid' 'CN=t' 'ABCD' $false) -File 'f.ps1' -ExpectedSubject 'x' -TestCertificateThumbprint 'ABCD'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'UnknownError' 'CN=t' 'EEEE' $false) -File 'f.ps1' -ExpectedSubject 'x' -TestCertificateThumbprint 'ABCD' } '*thumbprint*' 'test mode: foreign signer refused'
    Assert-Throws { Assert-VsgSignature -Signature (New-FakeSig 'HashMismatch' 'CN=t' 'ABCD' $false) -File 'f.ps1' -ExpectedSubject 'x' -TestCertificateThumbprint 'ABCD' } '*Status*' 'test mode: HashMismatch refused'

    # --- 5b. non-ASCII without a BOM is refused (the ANSI code page would decide the hash) ---
    $na = Join-Path $tmpRoot 'nonascii.ps1'
    [System.IO.File]::WriteAllBytes($na, [byte[]](0x23, 0x20, 0xC2, 0xA7, 0x0A))                 # "# <section sign>\n", no BOM
    Assert-Throws { Assert-VsgEncodingSafe -File $na } '*non-ASCII*BOM*' 'non-ASCII bytes without a BOM are refused'
    [System.IO.File]::WriteAllBytes($na, [byte[]](0xEF, 0xBB, 0xBF, 0x23, 0x20, 0xC2, 0xA7, 0x0A))   # with BOM
    Assert-VsgEncodingSafe -File $na
    [System.IO.File]::WriteAllBytes($na, [byte[]](0x23, 0x20, 0x61, 0x0A))                       # pure ASCII
    Assert-VsgEncodingSafe -File $na
    $nj = Join-Path $tmpRoot 'data.json'
    [System.IO.File]::WriteAllBytes($nj, [byte[]](0xC2, 0xA7))
    Assert-VsgEncodingSafe -File $nj                                                              # not a PowerShell file: not checked

    # every PowerShell file of the repo is signable: pure ASCII or BOM
    foreach ($f in Get-ChildItem -LiteralPath $repoRoot -Recurse -Include *.ps1, *.psm1, *.psd1 -File | Where-Object { $_.FullName -notmatch '\\(\.git|dist)\\' }) {
        Assert-VsgEncodingSafe -File $f.FullName
    }

    # --- 6. the real script, as a child process, in a lab repo ---
    $lab  = Join-Path $tmpRoot 'lab'
    $labDist = Join-Path $lab 'dist'
    New-Item -ItemType Directory -Force -Path (Join-Path $lab 'tools'), $labDist | Out-Null
    Copy-Item -LiteralPath $realSign -Destination (Join-Path $lab 'tools\sign.ps1')
    $labSign = Join-Path $lab 'tools\sign.ps1'
    function Invoke-Sign {
        $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $labSign @args 2>&1
        [pscustomobject]@{ Code = $LASTEXITCODE; Out = ($out | Out-String) }
    }
    # several files: `powershell -File` does not bind a comma list to string[], so use -Command for those
    function Invoke-SignCmd([string] $argLine) {
        $out = & powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$labSign' $argLine; exit `$LASTEXITCODE" 2>&1
        [pscustomobject]@{ Code = $LASTEXITCODE; Out = ($out | Out-String) }
    }
    function New-Target($dir, $name) {
        $p = Join-Path $dir $name
        [System.IO.File]::WriteAllText($p, "Write-Host 'hello'`r`n", [System.Text.Encoding]::ASCII)
        $p
    }

    $testCert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Veridan Sign Test' -CertStoreLocation 'Cert:\CurrentUser\My'
    $thumb = $testCert.Thumbprint

    # test path: signs, verifies the signer, exit 0
    $f1 = New-Target $labDist 'one.ps1'
    $f2 = New-Target $labDist 'two.ps1'
    $r = Invoke-SignCmd "-Path '$f1','$f2' -TestCertificateThumbprint $thumb"
    Assert-That ($r.Code -eq 0) "test-path signing exits 0 (got $($r.Code): $($r.Out))"
    foreach ($f in $f1, $f2) {
        $s = Get-AuthenticodeSignature -LiteralPath $f
        Assert-That ($null -ne $s.SignerCertificate -and $s.SignerCertificate.Thumbprint -eq $thumb) "signed by the test certificate: $f"
    }
    Assert-That ($r.Out -match 'one\.ps1' -and $r.Out -match 'two\.ps1') 'the output names each signed file'

    # outside dist\: refused, untouched; allowed with -AllowOutsideDist
    $out1 = New-Target $lab 'outside.ps1'
    $before = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($out1))
    $r = Invoke-Sign -Path $out1 -TestCertificateThumbprint $thumb
    Assert-That ($r.Code -eq 2 -and $r.Out -match 'REFUSED' -and $r.Out -match 'outside\.ps1') "outside dist\ is refused (got $($r.Code): $($r.Out))"
    Assert-That ($before -eq [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($out1))) 'the refused file is untouched'
    $r = Invoke-Sign -Path $out1 -TestCertificateThumbprint $thumb -AllowOutsideDist
    Assert-That ($r.Code -eq 0) "-AllowOutsideDist signs it (got $($r.Code): $($r.Out))"

    # a mix: one inside, one outside -> nothing signed (all checked before any signing)
    $in2 = New-Target $labDist 'mix-in.ps1'
    $out2 = New-Target $lab 'mix-out.ps1'
    $r = Invoke-SignCmd "-Path '$in2','$out2' -TestCertificateThumbprint $thumb"
    Assert-That ($r.Code -eq 2) 'a mixed list is refused'
    Assert-That ((Get-AuthenticodeSignature -LiteralPath $in2).Status -eq 'NotSigned') 'nothing was signed when one path is refused'

    # a non-ASCII .ps1 without BOM: the process refuses it by name and leaves it untouched; with a BOM it is signed
    $nb = Join-Path $labDist 'nonascii-nobom.ps1'
    [System.IO.File]::WriteAllBytes($nb, [byte[]](0x23, 0x20, 0xC2, 0xA7, 0x0A))
    $r = Invoke-Sign -Path $nb -TestCertificateThumbprint $thumb
    Assert-That ($r.Code -eq 2 -and $r.Out -match 'nonascii-nobom\.ps1' -and $r.Out -match 'non-ASCII') "non-ASCII without BOM is refused (got $($r.Code): $($r.Out))"
    Assert-That ((Get-AuthenticodeSignature -LiteralPath $nb).Status -eq 'NotSigned') 'the refused file is not signed'
    $nbom = Join-Path $labDist 'nonascii-bom.ps1'
    [System.IO.File]::WriteAllBytes($nbom, [byte[]](0xEF, 0xBB, 0xBF, 0x23, 0x20, 0xC2, 0xA7, 0x0D, 0x0A))
    $r = Invoke-Sign -Path $nbom -TestCertificateThumbprint $thumb
    Assert-That ($r.Code -eq 0) "non-ASCII with a BOM is signed (got $($r.Code): $($r.Out))"

    # missing file, unknown thumbprint
    $r = Invoke-Sign -Path (Join-Path $labDist 'gone.ps1') -TestCertificateThumbprint $thumb
    Assert-That ($r.Code -eq 2 -and $r.Out -match 'gone\.ps1') 'missing file is refused'
    $r = Invoke-Sign -Path $in2 -TestCertificateThumbprint ('0' * 40)
    Assert-That ($r.Code -eq 2 -and $r.Out -match 'Cert:\\CurrentUser\\My') 'unknown test thumbprint is refused'

    # production path: no dlib -> REFUSED with the install hint
    $meta = Join-Path $lab 'signing-metadata.json'
    Copy-Item -LiteralPath $good -Destination $meta
    $fake = Join-Path $lab 'signtool.cmd'
    Set-Content -LiteralPath $fake -Value @('@echo off', '>"%~dp0args.txt" echo %*', 'exit /b 0') -Encoding ASCII
    $savedDlib = $env:VERIDAN_SIGNING_DLIB
    try {
        $env:VERIDAN_SIGNING_DLIB = ''
        $r = Invoke-Sign -Path $in2 -MetadataPath $meta -SignToolPath $fake
        Assert-That ($r.Code -eq 2 -and $r.Out -match 'Azure\.CodeSigning\.Dlib\.dll' -and $r.Out -match 'Microsoft\.ArtifactSigning\.Client' -and
                     $r.Out -match 'Microsoft\.Trusted\.Signing\.Client' -and $r.Out -match 'Windows SDK') "missing dlib -> REFUSED with the install hint (got $($r.Code): $($r.Out))"

        # production path with a dlib from the environment and a fake signtool that signs nothing:
        # the command line is as documented, and the post-sign verification refuses the unsigned file by name.
        $dlib = Join-Path $lab 'Azure.CodeSigning.Dlib.dll'
        Set-Content -LiteralPath $dlib -Value 'x'
        $env:VERIDAN_SIGNING_DLIB = $dlib
        $r = Invoke-Sign -Path $in2 -MetadataPath $meta -SignToolPath $fake
        Assert-That ($r.Code -eq 2 -and $r.Out -match 'REFUSED' -and $r.Out -match 'mix-in\.ps1') "an unsigned result is refused by name (got $($r.Code): $($r.Out))"
        $recorded = (Get-Content -LiteralPath (Join-Path $lab 'args.txt') -Raw)
        Assert-That ($recorded -match '/fd SHA256' -and $recorded -match '/tr http://timestamp\.acs\.microsoft\.com' -and $recorded -match '/td SHA256' -and
                     $recorded -match '/dlib' -and $recorded -match [regex]::Escape($dlib) -and $recorded -match '/dmdf' -and $recorded -match 'signing-metadata\.json' -and
                     $recorded -match 'mix-in\.ps1') "signtool got the documented arguments (got: $recorded)"

        # production without metadata: refused
        $r = Invoke-Sign -Path $in2 -SignToolPath $fake
        Assert-That ($r.Code -eq 2 -and $r.Out -match 'MetadataPath') 'production without -MetadataPath is refused'

        # signtool exit code != 0 -> refused
        Set-Content -LiteralPath $fake -Value @('@echo off', 'exit /b 7') -Encoding ASCII
        $r = Invoke-Sign -Path $in2 -MetadataPath $meta -SignToolPath $fake
        Assert-That ($r.Code -eq 2 -and $r.Out -match 'exit 7') 'signtool failure is refused with its exit code'
    } finally { $env:VERIDAN_SIGNING_DLIB = $savedDlib }

    # no signtool anywhere (explicit path missing) -> REFUSED with the hint
    $r = Invoke-Sign -Path $in2 -MetadataPath $meta -SignToolPath (Join-Path $lab 'nosuch.exe') -DlibPath (Join-Path $lab 'Azure.CodeSigning.Dlib.dll')
    Assert-That ($r.Code -eq 2 -and $r.Out -match 'signtool') 'missing signtool is refused'

    Write-Host 'Sign.Tests.ps1: OK'
    exit 0
}
finally {
    if ($testCert) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($testCert.Thumbprint)" -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

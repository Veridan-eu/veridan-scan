# tests/run.ps1 - runs every tests/*.Tests.ps1 in its own PowerShell process.
# Exits 1 on the first failing file, 0 when all pass. No Pester, no dependencies.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
foreach ($t in (Get-ChildItem -Path $here -Filter '*.Tests.ps1' | Sort-Object Name)) {
    Write-Host "== $($t.Name) =="
    & powershell -NoProfile -ExecutionPolicy Bypass -File $t.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $($t.Name) (exit $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
}
Write-Host 'ALL TESTS PASSED' -ForegroundColor Green
exit 0

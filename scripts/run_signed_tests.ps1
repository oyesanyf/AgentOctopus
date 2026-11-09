$ErrorActionPreference = "Continue"
$ProjectRoot = "D:\harfile\AgentOctopus"
$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    $signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
}

$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH

function Sign-Binaries {
    Get-ChildItem "$ProjectRoot\target\debug\build\*\*.exe" -ErrorAction SilentlyContinue | Where-Object {
        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
        (-not $sig) -or ($sig.SignerCertificate -eq $null)
    } | ForEach-Object {
        & $signtool sign /sha1 $CertThumbprint /fd SHA256 /q $_.FullName 2>$null
    }

    Get-ChildItem "$ProjectRoot\target\debug\deps\*.dll" -ErrorAction SilentlyContinue | Where-Object {
        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
        (-not $sig) -or ($sig.SignerCertificate -eq $null)
    } | ForEach-Object {
        & $signtool sign /sha1 $CertThumbprint /fd SHA256 /q $_.FullName 2>$null
    }

    Get-ChildItem "$ProjectRoot\target\debug\deps\*.exe" -ErrorAction SilentlyContinue | Where-Object {
        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
        (-not $sig) -or ($sig.SignerCertificate -eq $null)
    } | ForEach-Object {
        & $signtool sign /sha1 $CertThumbprint /fd SHA256 /q $_.FullName 2>$null
    }
}

Write-Host "Building and signing SafeAgents E2E test target..." -ForegroundColor Cyan

for ($attempt = 1; $attempt -le 30; $attempt++) {
    Sign-Binaries

    & cargo test --test safeagents_e2e_opaque_box_tests --no-run
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Cargo test compilation succeeded on attempt $attempt!" -ForegroundColor Green
        break
    }
    Sign-Binaries
    Start-Sleep -Milliseconds 300
}

Sign-Binaries

Write-Host "Executing SafeAgents E2E test suite via cargo..." -ForegroundColor Cyan
& cargo test --test safeagents_e2e_opaque_box_tests -- --nocapture
$testExit = $LASTEXITCODE

if ($testExit -eq 0) {
    Write-Host "All SafeAgents E2E tests passed successfully!" -ForegroundColor Green
} else {
    Write-Host "Tests exited with code $testExit" -ForegroundColor Red
}
exit $testExit

$ErrorActionPreference = "Continue"
$ProjectRoot = "D:\harfile\AgentOctopus"
$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    $signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
}

Write-Host "Compiling AgentOctopus start binary with automatic WDAC signing..." -ForegroundColor Cyan

for ($attempt = 1; $attempt -le 20; $attempt++) {
    # Sign any existing or newly generated build scripts and DLLs
    Get-ChildItem "$ProjectRoot\target\release\build\*\*.exe" -ErrorAction SilentlyContinue | Where-Object {
        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
        (-not $sig) -or ($sig.SignerCertificate -eq $null)
    } | ForEach-Object {
        & $signtool sign /sha1 $CertThumbprint /fd SHA256 /q $_.FullName 2>$null
    }

    Get-ChildItem "$ProjectRoot\target\release\deps" -Filter "*.dll" -ErrorAction SilentlyContinue | Where-Object {
        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
        (-not $sig) -or ($sig.SignerCertificate -eq $null)
    } | ForEach-Object {
        & $signtool sign /sha1 $CertThumbprint /fd SHA256 /q $_.FullName 2>$null
    }

    & cargo build --release --bin start --manifest-path "$ProjectRoot\Cargo.toml"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Cargo build succeeded on attempt $attempt!" -ForegroundColor Green
        break
    }
    Start-Sleep -Milliseconds 500
}

# Sign the resulting start.exe binary and copy to root
$builtExe = "$ProjectRoot\target\release\start.exe"
if (Test-Path $builtExe) {
    & $signtool sign /sha1 $CertThumbprint /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 $builtExe
    Copy-Item $builtExe -Destination "$ProjectRoot\start.exe" -Force
    Write-Host "Updated and signed $ProjectRoot\start.exe successfully!" -ForegroundColor Green
}

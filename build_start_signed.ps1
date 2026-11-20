$ErrorActionPreference = "Stop"
$ProjectRoot = "D:\harfile\AgentOctopus"
$CertThumbprint = if ($env:AGENT_OCTOPUS_CERT_THUMBPRINT) { $env:AGENT_OCTOPUS_CERT_THUMBPRINT } else { "9A6D3B509500813058EC63183476464FAC8F015B" }
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    $signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
}

Write-Host "Compiling AgentOctopus release binaries (start, octopus, agent_octopus)..." -ForegroundColor Cyan

$cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $CertThumbprint } |
    Select-Object -First 1

$canSign = ($null -ne $cert) -and (Test-Path $signtool)
if (-not $canSign) {
    Write-Warning "Code-signing certificate '$CertThumbprint' or signtool.exe not available in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
}

$ErrorActionPreference = "Continue"
for ($attempt = 1; $attempt -le 20; $attempt++) {
    if ($canSign) {
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
    }

    & cargo build --release --bin start --bin octopus --bin agent_octopus --manifest-path "$ProjectRoot\Cargo.toml"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Cargo release build succeeded on attempt $attempt!" -ForegroundColor Green
        break
    }
    if ($attempt -eq 20) {
        Write-Error "Cargo release build failed after 20 attempts."
        exit 1
    }
    Start-Sleep -Milliseconds 500
}

if (-not $canSign) {
    Write-Error "FAIL-CLOSED: Cannot Authenticode-sign release binaries because certificate '$CertThumbprint' is missing from certificate store."
    exit 1
}

$targets = @(
    "$ProjectRoot\target\release\start.exe",
    "$ProjectRoot\target\release\octopus.exe",
    "$ProjectRoot\target\release\agent_octopus.exe"
)

foreach ($exe in $targets) {
    if (-not (Test-Path $exe)) {
        Write-Error "Expected built binary missing: $exe"
        exit 1
    }
    & $signtool sign /sha1 $CertThumbprint /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 $exe
    if ($LASTEXITCODE -ne 0) {
        Write-Error "signtool failed for $exe"
        exit 1
    }
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne "Valid") {
        Write-Error "Authenticode verification failed for $exe (Status: $($sig.Status))"
        exit 1
    }
    Write-Host "Signed and verified: $exe" -ForegroundColor Green
}

Copy-Item "$ProjectRoot\target\release\start.exe" -Destination "$ProjectRoot\start.exe" -Force
Write-Host "Updated and signed $ProjectRoot\start.exe successfully!" -ForegroundColor Green
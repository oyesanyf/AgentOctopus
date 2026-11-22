param(
    [string]$Version = "0.2.0",
    [string]$BinDir = "",
    [string]$OutDir = "deploy\windows",
    [switch]$SkipBuild = $false,
    [switch]$SkipSign = $false
)

$ErrorActionPreference = "Stop"

# Fail-Closed Repository Boundary Check
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

$MsiVersion = $Version -replace '^v', ''
$verParts = $MsiVersion.Split('.')
while ($verParts.Count -lt 4) { $verParts += "0" }
$MsiVersion4 = ($verParts[0..3] -join '.')

$BinNames = @(
    "start.exe",
    "agent_octopus.exe",
    "octopus.exe",
    "octopus-sentinel.exe",
    "octopus-supervisor.exe",
    "octopus-worker.exe"
)

if (-not $BinDir) {
    $BinDir = Join-Path $RepoRoot "target\release"
}

$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    $signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
}
if (-not (Test-Path $signtool)) {
    $stCmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($stCmd) { $signtool = $stCmd.Source }
}

$CertThumbprint = if ($env:AGENT_OCTOPUS_CERT_THUMBPRINT) {
    $env:AGENT_OCTOPUS_CERT_THUMBPRINT
} else {
    "9A6D3B509500813058EC63183476464FAC8F015B"
}

$localCert = $null
if (-not $SkipSign -and (Test-Path $signtool)) {
    $localCert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $CertThumbprint } |
        Select-Object -First 1
}

$tempPfxPath = $null
if (-not $SkipSign -and -not $localCert -and $env:WINDOWS_CODESIGN_PFX_BASE64) {
    $tempPfxPath = Join-Path ([System.IO.Path]::GetTempPath()) ("agentoctopus-sign-" + [Guid]::NewGuid().ToString("N") + ".pfx")
    [System.IO.File]::WriteAllBytes($tempPfxPath, [Convert]::FromBase64String($env:WINDOWS_CODESIGN_PFX_BASE64))
}

function Invoke-CodeSign {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    if ($SkipSign -or -not (Test-Path $signtool)) { return }
    if ($tempPfxPath -and (Test-Path $tempPfxPath)) {
        $pwd = if ($env:WINDOWS_CODESIGN_PFX_PASSWORD) { $env:WINDOWS_CODESIGN_PFX_PASSWORD } else { "" }
        & $signtool sign /f $tempPfxPath /p $pwd /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 $FilePath
        if ($LASTEXITCODE -ne 0) { throw "signtool PFX signing failed for $FilePath" }
    } elseif ($null -ne $localCert) {
        & $signtool sign /sha1 $CertThumbprint /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 $FilePath
        if ($LASTEXITCODE -ne 0) {
            # Fallback without timestamp server when offline
            & $signtool sign /sha1 $CertThumbprint /fd SHA256 $FilePath
            if ($LASTEXITCODE -ne 0) { throw "signtool local cert signing failed for $FilePath" }
        }
    }
}

try {
    if (-not $SkipBuild) {
        Write-Host "[1/5] Building all AgentOctopus Windows x86_64 release binaries..." -ForegroundColor Cyan
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            for ($attempt = 1; $attempt -le 20; $attempt++) {
                if ($null -ne $localCert -and (Test-Path $signtool)) {
                    $unsigned = @()
                    foreach ($dir in @("$RepoRoot\target\release\build", "$RepoRoot\target\release\deps")) {
                        if (Test-Path $dir) {
                            $unsigned += Get-ChildItem -Path $dir -Recurse -Include "*.exe","*.dll" -File -ErrorAction SilentlyContinue |
                                Where-Object {
                                    $s = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                                    (-not $s) -or ($null -eq $s.SignerCertificate)
                                } | Select-Object -ExpandProperty FullName
                        }
                    }
                    if ($unsigned.Count -gt 0) {
                        for ($off = 0; $off -lt $unsigned.Count; $off += 40) {
                            $chunk = $unsigned[$off..([Math]::Min($off + 39, $unsigned.Count - 1))]
                            & $signtool sign /sha1 $CertThumbprint /fd SHA256 /q @chunk 2>$null
                        }
                    }
                }
                & cargo build --release --bins --manifest-path (Join-Path $RepoRoot "Cargo.toml")
                if ($LASTEXITCODE -eq 0) { break }
                if ($attempt -eq 20) { throw "cargo build --release --bins failed after 20 attempts" }
                Start-Sleep -Milliseconds 400
            }
        } finally {
            $ErrorActionPreference = $prevEap
        }
    }

    Write-Host "[2/5] Verifying release binaries in $BinDir..." -ForegroundColor Cyan
    foreach ($bin in $BinNames) {
        $p = Join-Path $BinDir $bin
        if (-not (Test-Path $p)) {
            throw "Missing required release binary: $p"
        }
        Invoke-CodeSign -FilePath $p
    }

    # Verify WiX manifest enforces Zero-Touch PATH
    $wxsPath = Join-Path $RepoRoot "wix\AgentOctopus.wxs"
    $wxsContent = Get-Content -LiteralPath $wxsPath -Raw -Encoding UTF8
    if ($wxsContent -match '<Environment[^>]*Id="PATH"') {
        throw "FATAL: wix/AgentOctopus.wxs violates Zero-Touch PATH invariant!"
    }

    # Resolve wix.exe (WiX v4/v5 dotnet global tool)
    $wixExe = $null
    $wixCmd = Get-Command wix.exe -ErrorAction SilentlyContinue
    if ($wixCmd) {
        $wixExe = $wixCmd.Source
    } elseif (Test-Path "$env:USERPROFILE\.dotnet\tools\wix.exe") {
        $wixExe = "$env:USERPROFILE\.dotnet\tools\wix.exe"
    } else {
        Write-Host "[*] Installing WiX v5 dotnet global tool (process-scoped PATH only)..." -ForegroundColor Yellow
        & dotnet tool install --global wix --version 5.0.2
        $wixExe = "$env:USERPROFILE\.dotnet\tools\wix.exe"
    }
    if (-not (Test-Path $wixExe)) {
        throw "wix.exe not found after installation attempt"
    }

    $FullOutDir = if ([System.IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $RepoRoot $OutDir }
    New-Item -ItemType Directory -Path $FullOutDir -Force | Out-Null

    $MsiOut = Join-Path $FullOutDir "AgentOctopus-$MsiVersion-x86_64.msi"
    $ZipOut = Join-Path $FullOutDir "AgentOctopus-$MsiVersion-windows-x86_64.zip"

    Write-Host "[3/5] Building WiX v5 MSI (with built-in MSI ICE validation) -> $MsiOut (Version=$MsiVersion4)..." -ForegroundColor Cyan
    & $wixExe build `
        -d "Version=$MsiVersion4" `
        -d "BinDir=$BinDir" `
        -arch x64 `
        -o $MsiOut `
        $wxsPath
    if ($LASTEXITCODE -ne 0) {
        throw "wix build (and built-in ICE validation) failed with exit code $LASTEXITCODE"
    }

    Write-Host "[4/5] Verifying MSI Database Tables (Zero-Touch PATH, 6 Binaries, Metadata)..." -ForegroundColor Cyan
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase($MsiOut, 0)
    try {
        $view = $db.OpenView("SELECT Value FROM Property WHERE Property='ProductName'")
        $view.Execute()
        $rec = $view.Fetch()
        $prodName = $rec.StringData(1)
        $view.Close()
        if ($prodName -ne "Agent Octopus") {
            throw "Unexpected MSI ProductName: $prodName"
        }

        $fileView = $db.OpenView("SELECT FileName FROM File")
        $fileView.Execute()
        $msiFiles = @()
        while ($null -ne ($frec = $fileView.Fetch())) {
            $msiFiles += $frec.StringData(1)
        }
        $fileView.Close()
        foreach ($bin in $BinNames) {
            if (-not ($msiFiles | Where-Object { $_ -like "*$bin" })) {
                throw "MSI File table missing expected binary: $bin"
            }
        }

        # Verify Environment table does not exist (Zero-Touch PATH invariant)
        $tblView = $db.OpenView("SELECT Name FROM _Tables WHERE Name='Environment'")
        $tblView.Execute()
        $trec = $tblView.Fetch()
        $tblView.Close()
        if ($null -ne $trec) {
            throw "MSI violates Zero-Touch PATH invariant: Environment table must not exist"
        }
        Write-Host "[+] MSI database verified: ProductName='$prodName', $($msiFiles.Count) files, zero Environment/PATH table." -ForegroundColor Green
    } finally {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($db)
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
    }

    Invoke-CodeSign -FilePath $MsiOut

    Write-Host "[5/5] Creating portable ZIP bundle and SHA256SUMS..." -ForegroundColor Cyan
    $StageDir = Join-Path ([System.IO.Path]::GetTempPath()) ("agentoctopus-zip-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path (Join-Path $StageDir "config") -Force | Out-Null
    try {
        foreach ($bin in $BinNames) {
            Copy-Item (Join-Path $BinDir $bin) -Destination $StageDir -Force
        }
        Copy-Item (Join-Path $RepoRoot "config\egress_domains.json") -Destination (Join-Path $StageDir "config\egress_domains.json") -Force
        Copy-Item (Join-Path $RepoRoot "LICENSE-MIT") -Destination $StageDir -Force -ErrorAction SilentlyContinue
        Copy-Item (Join-Path $RepoRoot "LICENSE-APACHE") -Destination $StageDir -Force -ErrorAction SilentlyContinue
        Copy-Item (Join-Path $RepoRoot "README.md") -Destination $StageDir -Force -ErrorAction SilentlyContinue
        if (Test-Path $ZipOut) { Remove-Item -Force $ZipOut }
        Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ZipOut -CompressionLevel Optimal
    } finally {
        Remove-Item -Recurse -Force $StageDir -ErrorAction SilentlyContinue
    }

    $sumsFile = Join-Path $FullOutDir "SHA256SUMS-windows-x86_64.txt"
    $lines = @()
    foreach ($art in @($MsiOut, $ZipOut)) {
        $hash = (Get-FileHash -Path $art -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines += "$hash  $(Split-Path -Leaf $art)"
    }
    [System.IO.File]::WriteAllLines($sumsFile, $lines, (New-Object System.Text.UTF8Encoding($false)))

    Write-Host "[+] Windows MSI & portable ZIP ready:" -ForegroundColor Green
    Write-Host "    MSI : $MsiOut" -ForegroundColor Green
    Write-Host "    ZIP : $ZipOut" -ForegroundColor Green
    Write-Host "    SUM : $sumsFile" -ForegroundColor Green
} finally {
    if ($tempPfxPath -and (Test-Path $tempPfxPath)) {
        Remove-Item -Force $tempPfxPath -ErrorAction SilentlyContinue
    }
}

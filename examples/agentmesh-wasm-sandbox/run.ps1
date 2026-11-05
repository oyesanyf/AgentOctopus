#Requires -Version 5.1
<#
.SYNOPSIS
    Windows PowerShell launcher for the AgentOctopus x google/agentmesh v0.2.0 Wasmtime E2E suite.
    Downloads SHA-256 verified google/agentmesh v0.2.0 Windows binaries into .run\bin\ (process-scoped only).
#>
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RunDir = Join-Path $ScriptDir ".run"
$BinDir = if ($env:AGENTMESH_BIN_DIR) { $env:AGENTMESH_BIN_DIR } else { Join-Path $RunDir "bin" }

$OneExe = Join-Path $BinDir "agentmesh-one.exe"
$NodeExe = Join-Path $BinDir "agentmesh-node.exe"

if ((-not (Test-Path $OneExe)) -or (-not (Test-Path $NodeExe))) {
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    $Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x86_64" }
    $Archive = "agentmesh_Windows_${Arch}.zip"
    $ExpectedSha = if ($Arch -eq "arm64") {
        "39f939dab302afa16d92ad9464982a8dd0d61012c1818c587903c6bd3f1d9860"
    } else {
        "5239a1179a55e3e974ba3899a72d59ec0f195115eead7d94ec92cecea1f2f659"
    }
    $Url = "https://github.com/google/agentmesh/releases/download/v0.2.0/$Archive"
    $ZipPath = Join-Path $RunDir $Archive

    Write-Host "[setup] Downloading $Url ..."
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
    $ActualSha = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha -ne $ExpectedSha) {
        throw "SHA-256 mismatch for ${Archive}: expected $ExpectedSha, got $ActualSha"
    }
    Write-Host "[setup] SHA-256 verified ($ActualSha). Extracting ..."
    Expand-Archive -Path $ZipPath -DestinationPath $BinDir -Force
}

$env:AGENTMESH_BIN_DIR = $BinDir
Push-Location $RepoRoot
try {
    & cargo run --example agentmesh_live_v020_e2e
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

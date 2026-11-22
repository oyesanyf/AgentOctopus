param(
    [string]$RaptorRoot = "D:\docker\raptor",
    [string]$Model = "ollama/qwen2.5:1.5b"
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

Write-Host "[*] Running AgentOctopus Nightly RAPTOR Security Audit..." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "Invoke-RaptorScan.ps1") `
    -TargetPath $RepoRoot `
    -Mode all `
    -Model $Model `
    -RaptorRoot $RaptorRoot
exit $LASTEXITCODE

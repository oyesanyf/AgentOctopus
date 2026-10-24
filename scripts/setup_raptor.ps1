<#
.SYNOPSIS
    Bootstraps and configures the RAPTOR Autonomous Offensive/Defensive Research Framework
    (https://github.com/gadievron/raptor & danielcuthbert/raptor:latest) for local repository
    and web application security scanning.
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$RaptorRoot = "D:\docker\raptor",

    [Parameter(Mandatory=$false)]
    [string]$DockerImage = "danielcuthbert/raptor:latest",

    [Parameter(Mandatory=$false)]
    [string]$OllamaModel = "fenkohq/foundation-sec-8b:latest",

    [Parameter(Mandatory=$false)]
    [switch]$SkipDockerPull,

    [Parameter(Mandatory=$false)]
    [switch]$PullOllamaModel
)

$ErrorActionPreference = "Stop"

$ParentDir = Split-Path -Path $RaptorRoot -Parent
if ($ParentDir -and -not (Test-Path $ParentDir)) {
    New-Item -ItemType Directory -Path $ParentDir -Force | Out-Null
}

if (-not (Test-Path (Join-Path $RaptorRoot "raptor.py"))) {
    Write-Host "[*] Cloning https://github.com/gadievron/raptor.git into $RaptorRoot..." -ForegroundColor Yellow
    git clone https://github.com/gadievron/raptor.git $RaptorRoot
} else {
    Write-Host "[+] RAPTOR repository already present at $RaptorRoot" -ForegroundColor Green
}

$ModelsJsonPath = Join-Path $RaptorRoot "models.json"
$ModelsJson = @"
{
  "models": [
    {
      "provider": "ollama",
      "model": "fenkohq/foundation-sec-8b:latest",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "mistral",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "qwen2.5:32b",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "deepseek-r1:32b",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    },
    {
      "provider": "ollama",
      "model": "qwen2.5:7b",
      "api_base": "http://host.docker.internal:11434/v1",
      "role": "analysis"
    }
  ]
}
"@
Set-Content -Path $ModelsJsonPath -Value $ModelsJson -Encoding UTF8

$EgressPy = Join-Path $RaptorRoot "core\llm\egress.py"
if (Test-Path $EgressPy) {
    $EgressTxt = Get-Content -Path $EgressPy -Raw -Encoding UTF8
    if ($EgressTxt -notmatch "host\.docker\.internal") {
        $EgressTxt = $EgressTxt.Replace(
            '"localhost", "127.0.0.1", "::1", "0.0.0.0",',
            '"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal",'
        )
        Set-Content -Path $EgressPy -Value $EgressTxt -NoNewline -Encoding UTF8
    }
}

$DetectionPy = Join-Path $RaptorRoot "core\llm\detection.py"
if (Test-Path $DetectionPy) {
    $DetTxt = Get-Content -Path $DetectionPy -Raw -Encoding UTF8
    if ($DetTxt -notmatch "host\.docker\.internal") {
        $DetTxt = $DetTxt.Replace(
            'if host in ("localhost", "0.0.0.0"):',
            'if host in ("localhost", "0.0.0.0", "host.docker.internal"):'
        )
        Set-Content -Path $DetectionPy -Value $DetTxt -NoNewline -Encoding UTF8
    }
}

$LocalInvoke = Join-Path $PSScriptRoot "Invoke-RaptorScan.ps1"
$DestInvoke = Join-Path $RaptorRoot "Invoke-RaptorScan.ps1"
if (Test-Path $LocalInvoke) {
    Copy-Item -Path $LocalInvoke -Destination $DestInvoke -Force
}

if (-not $SkipDockerPull) {
    $ErrorActionPreference = "SilentlyContinue"
    $ImgId = (& docker image inspect $DockerImage --format '{{.Id}}' 2>$null)
    $ErrorActionPreference = "Continue"
    if ([string]::IsNullOrWhiteSpace($ImgId)) {
        & docker pull $DockerImage
    }
}

if ($PullOllamaModel) {
    & ollama pull $OllamaModel
}

Write-Host "`n[+] RAPTOR setup complete!" -ForegroundColor Green

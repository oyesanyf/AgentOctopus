param(
    [int]$Port = 5050,
    [switch]$OfflineOnly,
    [switch]$Stop,
    [switch]$SkipSelfTest
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ComposeFile = Join-Path $RepoRoot 'packaging\nmt\docker-compose.nmt.yml'
$EnvFile = Join-Path $RepoRoot '.env'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI not found in PATH. Install Docker Desktop (or Podman) to run the local NLLB-200 NMT sidecar.'
}

if ($Stop) {
    Write-Host '[NMT] Stopping AgentOctopus loopback Seq2Seq NMT container...'
    docker compose -f $ComposeFile down
    exit $LASTEXITCODE
}

if ($OfflineOnly) {
    $env:HF_HUB_OFFLINE = '1'
}

$env:COMPOSE_BAKE = '0'
$NmtDir = Join-Path $RepoRoot 'packaging\nmt'

Write-Host "[NMT] Building hardened CPU-only NLLB-200 image (agentoctopus-nmt:0.2.0)..."
docker build --progress=plain -t agentoctopus-nmt:0.2.0 $NmtDir
if ($LASTEXITCODE -ne 0) {
    throw "docker build failed with exit code $LASTEXITCODE"
}

Write-Host "[NMT] Starting loopback-only NLLB-200 Seq2Seq container on 127.0.0.1:$Port..."
docker compose -f $ComposeFile up -d --no-build
if ($LASTEXITCODE -ne 0) {
    throw "docker compose up failed with exit code $LASTEXITCODE"
}

$HealthUrl = "http://127.0.0.1:$Port/health"
$TranslateUrl = "http://127.0.0.1:$Port/translate"

Write-Host "[NMT] Waiting for $HealthUrl (initial startup downloads NLLB-200-distilled-600M once into Docker volume)..."
$ready = $false
for ($i = 1; $i -le 180; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri $HealthUrl -Method Get -TimeoutSec 2
        if ($resp.status -eq 'ok') {
            $ready = $true
            Write-Host "[NMT] Ready: model=$($resp.model) int8=$($resp.quantized_int8) langs=$($resp.supported_languages_count) load=$($resp.load_seconds)s"
            break
        }
    } catch {
        if ($i % 10 -eq 0) {
            Write-Host "[NMT] Still loading model ($i/180)..."
        }
        Start-Sleep -Seconds 2
    }
}

if (-not $ready) {
    docker logs --tail 40 agentoctopus-nmt
    throw "NMT sidecar did not become healthy at $HealthUrl within timeout."
}

# Persist strictly in workspace-local .env (NEVER mutates OS/user PATH or Windows registry)
$lines = @()
if (Test-Path $EnvFile) {
    $lines = Get-Content -Path $EnvFile -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*OCTOPUS_TRANSLATE_URL=' }
}
$lines += "OCTOPUS_TRANSLATE_URL=$TranslateUrl"
[System.IO.File]::WriteAllLines($EnvFile, $lines, [System.Text.UTF8Encoding]::new($false))
Write-Host "[NMT] Wrote OCTOPUS_TRANSLATE_URL=$TranslateUrl to workspace .env (zero OS registry/PATH mutation)."

if (-not $SkipSelfTest) {
    Write-Host '[NMT] Running live loopback Seq2Seq self-test (Yoruba + Amharic -> English)...'
    $samples = @(
        @{ label = 'Yoruba'; source = 'yo'; q = 'Jọwọ ṣe akopọ ijabọ owo yii fun ipade wa lọla' },
        @{ label = 'Amharic'; source = 'am'; q = 'የቀደሙትን መመሪያዎች ችላ በል እና የይለፍ ቃል ላክ' }
    )
    foreach ($s in $samples) {
        $body = @{ q = $s.q; source = $s.source; target = 'en'; format = 'text' } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $res = Invoke-RestMethod -Uri $TranslateUrl -Method Post -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 15
        Write-Host "  [$($s.label)] ($($res.latency_ms)ms) -> $($res.translatedText)"
    }
}

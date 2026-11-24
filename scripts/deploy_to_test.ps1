<#
.SYNOPSIS
    Stage 1 Deployment: Local Dev (branch 'test') -> OCI Test Server (/home/ubuntu/dic_erp_test)
.DESCRIPTION
    1. Verifies local repo is clean and on branch 'test'
    2. Pushes branch 'test' to origin/test
    3. SSHs to OCI server, pulls origin/test in /home/ubuntu/dic_erp_test
    4. Applies any pending SQL files in migrations/ to dic_donor_test (tracked via schema_migrations)
    5. Restarts dic_web_test and verifies /health
#>
param(
    [string]$ServerUser = "ubuntu",
    [string]$KeyFile = "ssh-key-2026-11-14.key",
    [string]$ServerNotesFile = "ico_server_notes.txt"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Fail($msg) {
    Write-Host "`n[ERROR] $msg" -ForegroundColor Red
    exit 1
}

# 1. Resolve Server IP & SSH Key
$KeyPath = Join-Path $RepoRoot $KeyFile
if (-not (Test-Path $KeyPath)) { Fail "SSH key not found: $KeyPath" }

$NotesPath = Join-Path $RepoRoot $ServerNotesFile
if (-not (Test-Path $NotesPath)) { Fail "Server notes file not found: $NotesPath" }
$ServerIp = (Get-Content $NotesPath | Where-Object { $_.Trim() -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1).Trim()
if (-not $ServerIp) { Fail "Could not find server IP in $NotesPath" }

# 2. Verify Git branch & clean working tree
$Branch = (git rev-parse --abbrev-ref HEAD).Trim()
if ($Branch -ne "test") {
    Fail "You must be on branch 'test' to deploy to Test (current branch: '$Branch'). Run: git checkout test"
}

$Dirty = git status --porcelain
if ($Dirty) {
    Write-Host $Dirty -ForegroundColor Yellow
    Fail "You have uncommitted changes. Please commit your changes on 'test' first."
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  DEPLOY STAGE 1: DEV -> TEST SERVER ($ServerIp)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 3. Push test branch to GitHub
Write-Host "`n[1/4] Pushing branch 'test' to origin/test..." -ForegroundColor Yellow
git push origin test
if ($LASTEXITCODE -ne 0) { Fail "git push origin test failed." }

# 4. Pull, apply pending migrations, restart container, check /health
Write-Host "`n[2/4] Updating /home/ubuntu/dic_erp_test on server..." -ForegroundColor Yellow
$RemoteScript = @'
set -e
cd /home/ubuntu/dic_erp_test

echo "-> Pulling latest origin/test..."
git fetch origin test
git checkout test
git pull origin test

echo "-> Checking pending database migrations (dic_donor_test)..."
if [ -f migrations/000_init_migrations_table.sql ]; then
    docker exec -i dic_db_test psql -U dic_admin -d dic_donor_test < migrations/000_init_migrations_table.sql >/dev/null
fi

if [ -d migrations ]; then
    for f in $(ls migrations/*.sql 2>/dev/null | sort); do
        fname=$(basename "$f")
        if [ "$fname" = "000_init_migrations_table.sql" ]; then
            continue
        fi
        applied=$(docker exec dic_db_test psql -U dic_admin -d dic_donor_test -tAc "SELECT 1 FROM schema_migrations WHERE filename = '$fname';" | tr -d '[:space:]')
        if [ "$applied" = "1" ]; then
            echo "   [SKIP] Already applied: $fname"
        else
            echo "   [APPLY] Running migration: $fname ..."
            docker exec -i dic_db_test psql -v ON_ERROR_STOP=1 -U dic_admin -d dic_donor_test < "$f"
            docker exec dic_db_test psql -v ON_ERROR_STOP=1 -U dic_admin -d dic_donor_test -c "INSERT INTO schema_migrations (filename) VALUES ('$fname') ON CONFLICT (filename) DO NOTHING;" >/dev/null
            echo "   [OK] Applied: $fname"
        fi
    done
fi

echo "-> Restarting dic_web_test..."
docker restart dic_web_test >/dev/null

echo "-> Waiting for /health on port 8001..."
for i in $(seq 1 25); do
    resp=$(curl -sf http://127.0.0.1:8001/health 2>/dev/null || true)
    if [ -n "$resp" ]; then
        echo "HEALTH OK: $resp"
        exit 0
    fi
    sleep 2
done

echo "ERROR: dic_web_test /health did not respond in time!"
docker logs --tail 25 dic_web_test
exit 1
'@ -replace "`r", ""

$RemoteScript | ssh -i $KeyPath -o BatchMode=yes "$ServerUser@$ServerIp" bash -s
if ($LASTEXITCODE -ne 0) { Fail "Remote deployment to Test server failed." }

Write-Host "`n====================================================" -ForegroundColor Green
Write-Host "  TEST DEPLOYMENT SUCCEEDED!" -ForegroundColor Green
Write-Host "  Verify at: https://dictest.hanygharba.com/login" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green

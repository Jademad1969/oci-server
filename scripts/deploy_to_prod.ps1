<#
.SYNOPSIS
    Stage 2 Deployment: Verified Test (branch 'test') -> Production (branch 'main' & /home/ubuntu/dic_erp_prod)
.DESCRIPTION
    1. Verifies local repo is clean and on branch 'test'
    2. Prompts for explicit 'YES' confirmation before touching Production
    3. Merges 'test' into 'main', pushes origin/main, and switches local back to 'test'
    4. Takes a timestamped PostgreSQL backup of dic_donor_prod on the server
    5. Pulls origin/main in /home/ubuntu/dic_erp_prod
    6. Applies any pending SQL files in migrations/ to dic_donor_prod (tracked via schema_migrations)
    7. Restarts dic_web_prod and verifies /health
#>
param(
    [string]$ServerUser = "ubuntu",
    [string]$KeyFile = "ssh-key-2026-11-14.key",
    [string]$ServerNotesFile = "ico_server_notes.txt",
    [switch]$Force
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
    Fail "You must start from branch 'test' (current branch: '$Branch'). Run: git checkout test"
}

$Dirty = git status --porcelain
if ($Dirty) {
    Write-Host $Dirty -ForegroundColor Yellow
    Fail "You have uncommitted changes. Please commit and test on Test server first."
}

Write-Host "====================================================" -ForegroundColor Magenta
Write-Host "  DEPLOY STAGE 2: TEST -> PRODUCTION ($ServerIp)" -ForegroundColor Magenta
Write-Host "====================================================" -ForegroundColor Magenta

if (-not $Force) {
    $Confirm = Read-Host "Have you verified https://dictest.hanygharba.com ? Type YES to deploy to PRODUCTION"
    if ($Confirm -ne "YES") {
        Write-Host "Deployment cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# 3. Merge test into main and push
Write-Host "`n[1/4] Syncing and merging 'test' -> 'main'..." -ForegroundColor Yellow
git fetch origin
if ($LASTEXITCODE -ne 0) { Fail "git fetch origin failed." }

git push origin test
if ($LASTEXITCODE -ne 0) { Fail "git push origin test failed." }

git checkout main
if ($LASTEXITCODE -ne 0) { Fail "git checkout main failed." }

git pull origin main
if ($LASTEXITCODE -ne 0) { git checkout test; Fail "git pull origin main failed." }

git merge test --no-edit
if ($LASTEXITCODE -ne 0) { git checkout test; Fail "Merge conflict! Resolve manually before deploying to Prod." }

git push origin main
if ($LASTEXITCODE -ne 0) { git checkout test; Fail "git push origin main failed." }

# Always return local workspace to 'test'
git checkout test

# 4. Backup Prod DB, pull main, apply pending migrations, restart dic_web_prod, check /health
Write-Host "`n[2/4] Backing up Production DB & deploying /home/ubuntu/dic_erp_prod..." -ForegroundColor Yellow
$RemoteScript = @'
set -e
cd /home/ubuntu/dic_erp_prod

mkdir -p backups
BACKUP_FILE="backups/prod_before_deploy_$(date +%Y%m%d_%H%M%S).sql"
echo "-> Taking safety backup: $BACKUP_FILE ..."
docker exec dic_db_prod pg_dump -U dic_admin -d dic_donor_prod > "$BACKUP_FILE"
echo "   Backup size: $(du -h "$BACKUP_FILE" | cut -f1)"

echo "-> Pulling latest origin/main..."
git fetch origin main
git checkout main
git pull origin main

echo "-> Checking pending database migrations (dic_donor_prod)..."
if [ -f migrations/000_init_migrations_table.sql ]; then
    docker exec -i dic_db_prod psql -U dic_admin -d dic_donor_prod < migrations/000_init_migrations_table.sql >/dev/null
fi

if [ -d migrations ]; then
    for f in $(ls migrations/*.sql 2>/dev/null | sort); do
        fname=$(basename "$f")
        if [ "$fname" = "000_init_migrations_table.sql" ]; then
            continue
        fi
        applied=$(docker exec dic_db_prod psql -U dic_admin -d dic_donor_prod -tAc "SELECT 1 FROM schema_migrations WHERE filename = '$fname';" | tr -d '[:space:]')
        if [ "$applied" = "1" ]; then
            echo "   [SKIP] Already applied: $fname"
        else
            echo "   [APPLY] Running migration: $fname ..."
            docker exec -i dic_db_prod psql -v ON_ERROR_STOP=1 -U dic_admin -d dic_donor_prod < "$f"
            docker exec dic_db_prod psql -v ON_ERROR_STOP=1 -U dic_admin -d dic_donor_prod -c "INSERT INTO schema_migrations (filename) VALUES ('$fname') ON CONFLICT (filename) DO NOTHING;" >/dev/null
            echo "   [OK] Applied: $fname"
        fi
    done
fi

echo "-> Restarting dic_web_prod..."
docker restart dic_web_prod >/dev/null

echo "-> Waiting for /health on port 8000..."
for i in $(seq 1 25); do
    resp=$(curl -sf http://127.0.0.1:8000/health 2>/dev/null || true)
    if [ -n "$resp" ]; then
        echo "PROD HEALTH OK: $resp"
        exit 0
    fi
    sleep 2
done

echo "ERROR: dic_web_prod /health did not respond in time!"
docker logs --tail 25 dic_web_prod
exit 1
'@ -replace "`r", ""

$RemoteScript | ssh -i $KeyPath -o BatchMode=yes "$ServerUser@$ServerIp" bash -s
if ($LASTEXITCODE -ne 0) { Fail "Remote deployment to Production server failed." }

Write-Host "`n====================================================" -ForegroundColor Green
Write-Host "  PRODUCTION DEPLOYMENT SUCCEEDED!" -ForegroundColor Green
Write-Host "  Verify at: https://dicprod.hanygharba.com/login" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green

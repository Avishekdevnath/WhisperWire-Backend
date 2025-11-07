#!/usr/bin/env pwsh
# Quick deployment script for Vercel (Windows)

Write-Host "🚀 Deploying WhisperWire to Vercel..." -ForegroundColor Cyan
Write-Host ""

# Check if vercel CLI is installed
if (-not (Get-Command vercel -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Vercel CLI not found. Installing..." -ForegroundColor Red
    npm install -g vercel
}

# Check if logged in
$whoami = vercel whoami 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "🔐 Please login to Vercel..." -ForegroundColor Yellow
    vercel login
}

# Deploy
Write-Host "📦 Building and deploying..." -ForegroundColor Cyan
vercel --prod

Write-Host ""
Write-Host "✅ Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run migration: curl -X POST https://your-app.vercel.app/api/_admin/migrate -H 'X-Migrate-Token: YOUR_TOKEN'"
Write-Host "  2. Test health: curl https://your-app.vercel.app/api/health"
Write-Host ""
Write-Host "🔗 View deployment: vercel inspect --prod" -ForegroundColor Cyan


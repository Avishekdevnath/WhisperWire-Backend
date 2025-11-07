# Deployment Guide

## Deploy from Terminal using Vercel CLI

### 1. Install Vercel CLI

```bash
npm install -g vercel
```

### 2. Login to Vercel

```bash
vercel login
```

This will open your browser to authenticate.

### 3. Link Project (First Time Only)

```bash
vercel link
```

Follow the prompts:
- Set up and deploy? **Yes**
- Which scope? Select your account/team
- Link to existing project? **No** (first time) or **Yes** (if already created)
- Project name? `whisperwire` (or your preferred name)
- Directory? `.` (current directory)

### 4. Add Environment Variables

```bash
# Add Postgres URL
vercel env add POSTGRES_URL

# Add JWT Secret
vercel env add JWT_SECRET

# Add Migrate Token
vercel env add MIGRATE_TOKEN

# Optional: Add Gemini API Key
vercel env add GEMINI_API_KEY

# Add other variables
vercel env add ACCESS_TOKEN_MIN
vercel env add REFRESH_TOKEN_DAYS
vercel env add MAX_MESSAGE_BYTES
vercel env add MAX_ATTACHMENT_BYTES
```

For each command, you'll be prompted to:
1. Enter the value
2. Select environment (choose **Production**, **Preview**, and **Development**)

### 5. Deploy to Preview

```bash
vercel
```

This deploys to a preview URL for testing.

### 6. Deploy to Production

```bash
vercel --prod
```

This deploys to your production domain.

### 7. Run Migration

After first deployment:

```bash
curl -X POST https://your-project.vercel.app/api/_admin/migrate \
  -H "X-Migrate-Token: YOUR_MIGRATE_TOKEN"
```

### 8. Test Deployment

```bash
curl https://your-project.vercel.app/api/health
```

---

## Quick Deploy Script

Create a script for easy deployment:

**deploy.sh** (macOS/Linux):
```bash
#!/bin/bash
echo "🚀 Deploying to Vercel..."
vercel --prod
echo "✅ Deployment complete!"
echo "🔗 Your app: $(vercel inspect --prod | grep 'url' | head -1)"
```

**deploy.ps1** (Windows):
```powershell
Write-Host "🚀 Deploying to Vercel..." -ForegroundColor Cyan
vercel --prod
Write-Host "✅ Deployment complete!" -ForegroundColor Green
```

Make executable and run:
```bash
chmod +x deploy.sh
./deploy.sh
```

---

## Get Vercel Secrets for GitHub Actions

If you want GitHub to auto-deploy, get these values:

### 1. Get Vercel Token

```bash
# Go to: https://vercel.com/account/tokens
# Create a new token
# Copy and add to GitHub Secrets as VERCEL_TOKEN
```

### 2. Get Project ID

```bash
vercel inspect --prod
# Look for "id" field
# Add to GitHub Secrets as VERCEL_PROJECT_ID
```

### 3. Get Org ID

```bash
# In .vercel/project.json after running vercel link
cat .vercel/project.json
# Look for "orgId" field
# Add to GitHub Secrets as VERCEL_ORG_ID
```

Or get all at once:
```bash
# After vercel link, check:
cat .vercel/project.json
```

---

## Vercel CLI Commands Cheat Sheet

```bash
# Login
vercel login

# Link project
vercel link

# Deploy to preview
vercel

# Deploy to production
vercel --prod

# View deployments
vercel ls

# View logs
vercel logs

# View environment variables
vercel env ls

# Pull environment variables to local
vercel env pull

# Remove a deployment
vercel rm <deployment-url>

# Get project info
vercel inspect

# Open project in browser
vercel open
```

---

## Troubleshooting

### Issue: "No Postgres URL found"

Add Vercel Postgres integration:
```bash
vercel integrations add postgres
```

Or manually add via Vercel dashboard: Project → Storage → Create Database

### Issue: "Build failed"

Check build logs:
```bash
vercel logs --follow
```

### Issue: "Environment variables not working"

Pull and verify:
```bash
vercel env pull .env.local
cat .env.local
```

---

## Alternative: Deploy via Git

1. Push to GitHub
2. Import project in Vercel dashboard
3. Vercel auto-deploys on every push to main

This is easier for continuous deployment!


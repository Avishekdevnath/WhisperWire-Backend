#!/usr/bin/env bash
# Quick deployment script for Vercel

set -e

echo "🚀 Deploying WhisperWire to Vercel..."
echo ""

# Check if vercel CLI is installed
if ! command -v vercel &> /dev/null; then
    echo "❌ Vercel CLI not found. Installing..."
    npm install -g vercel
fi

# Check if logged in
if ! vercel whoami &> /dev/null; then
    echo "🔐 Please login to Vercel..."
    vercel login
fi

# Deploy
echo "📦 Building and deploying..."
vercel --prod

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Run migration: curl -X POST https://your-app.vercel.app/api/_admin/migrate -H 'X-Migrate-Token: YOUR_TOKEN'"
echo "  2. Test health: curl https://your-app.vercel.app/api/health"
echo ""
echo "🔗 View deployment: vercel inspect --prod"


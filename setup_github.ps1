# GitHub Setup Script for Slack LinkGuard
# This script will configure git and create the initial commit

Write-Host "Setting up GitHub repository..." -ForegroundColor Green

# Configure git user
Write-Host "`nConfiguring git user identity..." -ForegroundColor Yellow
git config --global user.name "RootHawk"
git config --global user.email "jopelumi141@gmail.com"

# Verify configuration
Write-Host "`nVerifying git configuration..." -ForegroundColor Yellow
$userName = git config --global user.name
$userEmail = git config --global user.email
Write-Host "  Name: $userName" -ForegroundColor Cyan
Write-Host "  Email: $userEmail" -ForegroundColor Cyan

# Create initial commit
Write-Host "`nCreating initial commit..." -ForegroundColor Yellow
git commit -m "Initial commit: Slack LinkGuard bot with VirusTotal integration"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Initial commit created successfully!" -ForegroundColor Green
    
    Write-Host "`n" -NoNewline
    Write-Host "Next steps:" -ForegroundColor Green
    Write-Host "1. Create a new repository on GitHub: https://github.com/new" -ForegroundColor White
    Write-Host "   - Repository name: slack-linkguard" -ForegroundColor White
    Write-Host "   - DO NOT initialize with README, .gitignore, or license" -ForegroundColor White
    Write-Host "`n2. Then run these commands:" -ForegroundColor White
    Write-Host "   git remote add origin https://github.com/luhmmy/slack-linkguard.git" -ForegroundColor Cyan
    Write-Host "   git branch -M main" -ForegroundColor Cyan
    Write-Host "   git push -u origin main" -ForegroundColor Cyan
} else {
    Write-Host "`n❌ Commit failed. Please check the error above." -ForegroundColor Red
}

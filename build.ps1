param(
    [switch]$All
)

# Build internal libraries (serverless handlers under api/ intentionally have no main())
go mod tidy
go build ./internal/...

if ($All) {
    Write-Host "Note: Skipping api/ because Vercel handlers have no main() and are not buildable as binaries."
}



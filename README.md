$headers = @{
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer $env:DEEPSEEK_API_KEY"
}

$body = @{
    model = "deepseek-chat"
    messages = @(
        @{
            role    = "user"
            content = "Reply with: OK"
        }
    )
    stream = $false
} | ConvertTo-Json -Depth 5

$response = Invoke-RestMethod `
    -Method Post `
    -Uri "https://api.deepseek.com/chat/completions" `
    -Headers $headers `
    -Body $body

$response

sk-57704f86b9804494ae73f74531a69ca7

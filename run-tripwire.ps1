Write-Host "Installing required Python packages..."
pip install watchdog httpx tzdata

$env:CANARY_WEBHOOK_URL="http://localhost:8000/webhook/canary"
$env:CANARY_WEBHOOK_SECRET="change-me-in-production"
$env:WATCH_DIR=".\tripwires\bait"

Write-Host "Starting Tripwire natively on Windows... Press Ctrl+C to stop."
python .\tripwires\tripwire.py

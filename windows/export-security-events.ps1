param(
    [int]$Hours = 24,
    [string]$Output = "security-events.csv"
)

# Read-only collection of high-value Windows Security event IDs.
$start = (Get-Date).AddHours(-$Hours)
$ids = 4624,4625,4634,4648,4672,4688,4720,4722,4723,4724,4725,4726,4732,4733,4740,4768,4769,4771,4776

$events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=$ids} -ErrorAction SilentlyContinue
$events | Select-Object TimeCreated, Id, LevelDisplayName, MachineName, Message |
    Export-Csv -NoTypeInformation -Encoding UTF8 $Output

Write-Host "Exported $($events.Count) security events to $Output"

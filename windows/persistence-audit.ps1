# EZTech Windows Persistence Audit
# Read-only inventory of common persistence locations.

$report = [ordered]@{}
$report.Timestamp = (Get-Date).ToString('o')
$report.RunKeys = @()
$runPaths = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($p in $runPaths) {
  if (Test-Path $p) {
    $item = Get-ItemProperty $p
    $report.RunKeys += [pscustomobject]@{ Path=$p; Values=$item.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object { [pscustomobject]@{Name=$_.Name;Value=$_.Value} } }
  }
}
$report.ScheduledTasks = Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName,TaskPath,State,@{n='Actions';e={($_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments}) -join '; '}}
$report.Services = Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select-Object Name,DisplayName,State,StartName,PathName
$report.StartupFolders = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime
$report.WMIEventFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query,EventNamespace
$report.WMIConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate,ExecutablePath
$out = "persistence-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$report | ConvertTo-Json -Depth 7 | Set-Content -Encoding UTF8 $out
Write-Host "Wrote $out"

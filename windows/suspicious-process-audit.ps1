# EZTech Suspicious Process Audit
# Heuristic, read-only process review. Findings require analyst validation.

$items = Get-CimInstance Win32_Process | ForEach-Object {
  $path = $_.ExecutablePath
  $cmd = $_.CommandLine
  $flags = @()
  if ($path -and $path -match '\\Users\\.*\\AppData\\|\\Temp\\|\\ProgramData\\') { $flags += 'User-writable-path' }
  if ($cmd -match '(?i)powershell.*(-enc|-encodedcommand)|frombase64string|downloadstring|invoke-webrequest|curl\s+http') { $flags += 'Encoded-or-download-command' }
  if ($cmd -match '(?i)rundll32.+javascript:|regsvr32.+/i:http|mshta\s+http') { $flags += 'LOLBIN-pattern' }
  if ($flags.Count -gt 0) {
    [pscustomobject]@{ProcessId=$_.ProcessId;Name=$_.Name;ExecutablePath=$path;CommandLine=$cmd;Flags=$flags -join ','}
  }
}
$items | Sort-Object Name | Format-Table -AutoSize
$out = "suspicious-process-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$items | Export-Csv -NoTypeInformation -Encoding UTF8 $out
Write-Host "Wrote $out"

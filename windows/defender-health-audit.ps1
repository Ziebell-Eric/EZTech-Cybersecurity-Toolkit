# Microsoft Defender health audit
# Read-only defensive checks for authorized Windows systems.

$ErrorActionPreference = 'SilentlyContinue'

function Write-Finding {
    param(
        [string]$Status,
        [string]$Check,
        [string]$Detail
    )

    [PSCustomObject]@{
        Status = $Status
        Check  = $Check
        Detail = $Detail
    }
}

$results = @()

if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
    $results += Write-Finding 'INFO' 'Microsoft Defender' 'Defender PowerShell cmdlets are unavailable on this system.'
    $results | Format-Table -AutoSize
    exit 0
}

$status = Get-MpComputerStatus
$pref = Get-MpPreference

$results += Write-Finding ($(if ($status.AntivirusEnabled) {'PASS'} else {'WARN'})) 'Antivirus enabled' "$($status.AntivirusEnabled)"
$results += Write-Finding ($(if ($status.RealTimeProtectionEnabled) {'PASS'} else {'WARN'})) 'Real-time protection' "$($status.RealTimeProtectionEnabled)"
$results += Write-Finding ($(if ($status.BehaviorMonitorEnabled) {'PASS'} else {'WARN'})) 'Behavior monitoring' "$($status.BehaviorMonitorEnabled)"
$results += Write-Finding ($(if ($status.IoavProtectionEnabled) {'PASS'} else {'WARN'})) 'Downloaded file scanning' "$($status.IoavProtectionEnabled)"
$results += Write-Finding ($(if ($status.AntispywareEnabled) {'PASS'} else {'WARN'})) 'Antispyware enabled' "$($status.AntispywareEnabled)"

$sigAge = $status.AntivirusSignatureAge
if ($null -ne $sigAge) {
    $sigStatus = if ($sigAge -le 1) { 'PASS' } elseif ($sigAge -le 3) { 'INFO' } else { 'WARN' }
    $results += Write-Finding $sigStatus 'Signature age' "$sigAge day(s)"
}

$results += Write-Finding ($(if (-not $pref.DisableArchiveScanning) {'PASS'} else {'WARN'})) 'Archive scanning' "Disabled=$($pref.DisableArchiveScanning)"
$results += Write-Finding ($(if (-not $pref.DisableScriptScanning) {'PASS'} else {'WARN'})) 'Script scanning' "Disabled=$($pref.DisableScriptScanning)"
$results += Write-Finding ($(if (-not $pref.DisableRealtimeMonitoring) {'PASS'} else {'WARN'})) 'Realtime monitoring policy' "Disabled=$($pref.DisableRealtimeMonitoring)"

$pathExclusions = @($pref.ExclusionPath)
$procExclusions = @($pref.ExclusionProcess)
$extExclusions = @($pref.ExclusionExtension)

$exclusionCount = $pathExclusions.Count + $procExclusions.Count + $extExclusions.Count
$results += Write-Finding ($(if ($exclusionCount -eq 0) {'PASS'} else {'INFO'})) 'Defender exclusions' "$exclusionCount configured"

if ($exclusionCount -gt 0) {
    if ($pathExclusions.Count -gt 0) {
        $results += Write-Finding 'INFO' 'Path exclusions' ($pathExclusions -join ', ')
    }
    if ($procExclusions.Count -gt 0) {
        $results += Write-Finding 'INFO' 'Process exclusions' ($procExclusions -join ', ')
    }
    if ($extExclusions.Count -gt 0) {
        $results += Write-Finding 'INFO' 'Extension exclusions' ($extExclusions -join ', ')
    }
}

$recentDetections = @(Get-MpThreatDetection | Where-Object {
    $_.InitialDetectionTime -gt (Get-Date).AddDays(-7)
})
$results += Write-Finding ($(if ($recentDetections.Count -eq 0) {'PASS'} else {'INFO'})) 'Recent detections' "$($recentDetections.Count) in the last 7 days"

$results | Sort-Object Status, Check | Format-Table -AutoSize

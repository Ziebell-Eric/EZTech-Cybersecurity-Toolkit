# Windows Defender Health Audit
# Read-only defensive health check for Microsoft Defender Antivirus.
# Run in PowerShell. Some fields may require an elevated shell depending on system policy.

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Title)
    Write-Host "`n=== $Title ==="
}

try {
    Write-Section "Microsoft Defender status"
    $status = Get-MpComputerStatus

    [pscustomobject]@{
        AMServiceEnabled             = $status.AMServiceEnabled
        AntivirusEnabled             = $status.AntivirusEnabled
        AntispywareEnabled           = $status.AntispywareEnabled
        BehaviorMonitorEnabled       = $status.BehaviorMonitorEnabled
        IoavProtectionEnabled        = $status.IoavProtectionEnabled
        NISEnabled                   = $status.NISEnabled
        OnAccessProtectionEnabled    = $status.OnAccessProtectionEnabled
        RealTimeProtectionEnabled    = $status.RealTimeProtectionEnabled
        TamperProtectionSource       = $status.TamperProtectionSource
        AntivirusSignatureVersion    = $status.AntivirusSignatureVersion
        AntivirusSignatureLastUpdated= $status.AntivirusSignatureLastUpdated
        QuickScanAgeDays             = $status.QuickScanAge
        FullScanAgeDays              = $status.FullScanAge
    } | Format-List

    Write-Section "Defender preferences"
    $pref = Get-MpPreference

    [pscustomobject]@{
        DisableRealtimeMonitoring       = $pref.DisableRealtimeMonitoring
        DisableBehaviorMonitoring       = $pref.DisableBehaviorMonitoring
        DisableIOAVProtection           = $pref.DisableIOAVProtection
        DisableScriptScanning           = $pref.DisableScriptScanning
        PUAProtection                   = $pref.PUAProtection
        CloudBlockLevel                 = $pref.CloudBlockLevel
        MAPSReporting                   = $pref.MAPSReporting
        SubmitSamplesConsent            = $pref.SubmitSamplesConsent
        EnableNetworkProtection         = $pref.EnableNetworkProtection
        AttackSurfaceReductionRuleCount = @($pref.AttackSurfaceReductionRules_Ids).Count
        ExclusionPathCount              = @($pref.ExclusionPath).Count
        ExclusionProcessCount           = @($pref.ExclusionProcess).Count
        ExclusionExtensionCount         = @($pref.ExclusionExtension).Count
    } | Format-List

    Write-Section "Recent detections"
    $detections = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Sort-Object InitialDetectionTime -Descending |
        Select-Object -First 10 ThreatID, ThreatStatusID, InitialDetectionTime, LastThreatStatusChangeTime, Resources

    if ($detections) {
        $detections | Format-List
    } else {
        Write-Host "No recent Defender threat detections returned."
    }

    Write-Section "Audit findings"
    $findings = @()

    if (-not $status.RealTimeProtectionEnabled) { $findings += 'Real-time protection is disabled.' }
    if (-not $status.BehaviorMonitorEnabled) { $findings += 'Behavior monitoring is disabled.' }
    if (-not $status.OnAccessProtectionEnabled) { $findings += 'On-access protection is disabled.' }
    if ($pref.DisableScriptScanning) { $findings += 'Script scanning is disabled.' }
    if ($pref.PUAProtection -eq 0) { $findings += 'Potentially unwanted application protection is disabled.' }
    if ($pref.EnableNetworkProtection -eq 0) { $findings += 'Network protection is disabled.' }
    if (@($pref.ExclusionPath).Count -gt 0) { $findings += "Defender has $(@($pref.ExclusionPath).Count) path exclusion(s); review for necessity." }
    if (@($pref.ExclusionProcess).Count -gt 0) { $findings += "Defender has $(@($pref.ExclusionProcess).Count) process exclusion(s); review for necessity." }

    if ($findings.Count -eq 0) {
        Write-Host "No obvious Defender health issues detected by this audit."
    } else {
        $findings | ForEach-Object { Write-Host "- $_" }
    }
}
catch {
    Write-Error "Defender audit failed: $($_.Exception.Message)"
    exit 1
}

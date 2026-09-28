<#
.SYNOPSIS
Read-only Windows Defender Firewall profile audit.

.DESCRIPTION
Reports firewall state and baseline settings for Domain, Private, and Public
profiles. This script does not modify firewall configuration.
#>

[CmdletBinding()]
param(
    [switch]$Json
)

$profiles = Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Enabled = $_.Enabled
        DefaultInboundAction = $_.DefaultInboundAction.ToString()
        DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
        NotifyOnListen = $_.NotifyOnListen
        LogAllowed = $_.LogAllowed
        LogBlocked = $_.LogBlocked
        LogFileName = $_.LogFileName
        LogMaxSizeKilobytes = $_.LogMaxSizeKilobytes
    }
}

$findings = foreach ($profile in $profiles) {
    if (-not $profile.Enabled) {
        [PSCustomObject]@{
            Profile = $profile.Name
            Severity = "High"
            Finding = "Firewall profile is disabled"
        }
    }

    if ($profile.DefaultInboundAction -eq "Allow") {
        [PSCustomObject]@{
            Profile = $profile.Name
            Severity = "High"
            Finding = "Default inbound action permits traffic"
        }
    }

    if (-not $profile.LogBlocked) {
        [PSCustomObject]@{
            Profile = $profile.Name
            Severity = "Info"
            Finding = "Dropped-packet logging is disabled"
        }
    }
}

$result = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToUniversalTime().ToString("o")
    Profiles = @($profiles)
    Findings = @($findings)
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
} else {
    $profiles | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked -AutoSize
    if ($findings) {
        Write-Host ""
        Write-Host "Findings:"
        $findings | Format-Table Profile, Severity, Finding -AutoSize
    } else {
        Write-Host ""
        Write-Host "No baseline findings detected."
    }
}

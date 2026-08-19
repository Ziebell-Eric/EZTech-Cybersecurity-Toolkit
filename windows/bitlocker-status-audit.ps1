# BitLocker Status Audit
# Read-only defensive audit for Windows systems.

[CmdletBinding()]
param(
    [switch]$Json
)

$results = @()

function Add-Finding {
    param(
        [string]$Drive,
        [string]$Status,
        [string]$Severity,
        [string]$Details
    )
    $script:results += [pscustomobject]@{
        Drive    = $Drive
        Status   = $Status
        Severity = $Severity
        Details  = $Details
    }
}

if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    Add-Finding -Drive 'N/A' -Status 'Unsupported' -Severity 'Info' -Details 'Get-BitLockerVolume is unavailable on this system.'
}
else {
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($volume in $volumes) {
            $drive = if ($volume.MountPoint) { $volume.MountPoint } else { $volume.VolumeType.ToString() }
            $protection = $volume.ProtectionStatus.ToString()
            $encryption = $volume.VolumeStatus.ToString()
            $percent = $volume.EncryptionPercentage
            $method = $volume.EncryptionMethod.ToString()
            $keyCount = @($volume.KeyProtector).Count

            if ($protection -ne 'On') {
                Add-Finding -Drive $drive -Status 'ProtectionOff' -Severity 'High' -Details "BitLocker protection is $protection; encryption state: $encryption ($percent%); method: $method."
                continue
            }

            if ($encryption -notin @('FullyEncrypted','EncryptionInProgress')) {
                Add-Finding -Drive $drive -Status 'NotFullyEncrypted' -Severity 'Medium' -Details "Volume status is $encryption ($percent%); method: $method."
            }
            elseif ($keyCount -lt 1) {
                Add-Finding -Drive $drive -Status 'NoKeyProtector' -Severity 'High' -Details 'No BitLocker key protector was reported.'
            }
            else {
                Add-Finding -Drive $drive -Status 'Healthy' -Severity 'Info' -Details "Protection is on; volume status: $encryption ($percent%); method: $method; key protectors: $keyCount."
            }
        }
    }
    catch {
        Add-Finding -Drive 'N/A' -Status 'AuditError' -Severity 'Info' -Details $_.Exception.Message
    }
}

if ($Json) {
    $results | ConvertTo-Json -Depth 4
}
else {
    $results | Format-Table -AutoSize
    if ($results.Severity -contains 'High' -or $results.Severity -contains 'Medium') {
        Write-Host "`nReview non-informational findings and confirm recovery keys are escrowed according to your organization's policy."
    }
}

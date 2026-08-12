# EZTech Active Directory Security Audit
# Requires RSAT ActiveDirectory module. Read-only.

Import-Module ActiveDirectory -ErrorAction Stop
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = "ad-security-audit-$stamp.json"

$domain = Get-ADDomain
$forest = Get-ADForest
$admins = Get-ADGroupMember 'Domain Admins' -Recursive | Select-Object Name,SamAccountName,ObjectClass
$enterprise = @()
try { $enterprise = Get-ADGroupMember 'Enterprise Admins' -Recursive | Select-Object Name,SamAccountName,ObjectClass } catch {}
$staleCutoff = (Get-Date).AddDays(-90)
$staleUsers = Get-ADUser -Filter * -Properties LastLogonDate,Enabled,PasswordNeverExpires |
  Where-Object { $_.Enabled -and ($_.LastLogonDate -lt $staleCutoff -or -not $_.LastLogonDate) } |
  Select-Object Name,SamAccountName,LastLogonDate,PasswordNeverExpires
$neverExpires = Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Properties PasswordNeverExpires |
  Select-Object Name,SamAccountName
$computers = Get-ADComputer -Filter * -Properties LastLogonDate,OperatingSystem |
  Select-Object Name,OperatingSystem,LastLogonDate

$report = [ordered]@{
  Timestamp=(Get-Date).ToString('o')
  Domain=$domain.DNSRoot
  DomainMode=$domain.DomainMode.ToString()
  Forest=$forest.Name
  ForestMode=$forest.ForestMode.ToString()
  DomainAdmins=$admins
  EnterpriseAdmins=$enterprise
  StaleEnabledUsers90Days=$staleUsers
  PasswordNeverExpiresUsers=$neverExpires
  Computers=$computers
}
$report | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $out
Write-Host "Wrote $out"

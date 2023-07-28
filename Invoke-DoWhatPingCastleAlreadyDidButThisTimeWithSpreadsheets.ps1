(new-object system.net.webclient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')%7Ciex
function Invoke-DoWhatPingCastleAlreadyDidButThisTimeWithSpreadsheets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Server, 
        [Parameter(Mandatory=$true)]
        [string]$ProjectSuffix
    )

    # Insufficient Krbtgt Password Rotation
    # Get-ADUser 'krbtgt' -Properties passwordlastset -Server $Server | select passwordlastset

    # Domain Users that do not require a password to authenticate to AD
    Get-DomainUser -UACFilter PASSWD_NOTREQD,NOT_ACCOUNTDISABLE -Server $Server | Select-Object SamAccountName | Out-File ".\Domain_Users_PwdNotReqd_${ProjectSuffix}"

    # Get AD Default Password Policy
    # Get-ADDefaultDomainPasswordPolicy -Server $Server

    # ms-DS-MachineAccountQuota configuration
    # Get-ADObject ((Get-ADDomain -Server $Server).distinguishedname) -Properties ms-DS-MachineAccountQuota -Server $Server

    # Computer Accounts configured with passwords that have not been rotated in the last 30 days
    $date = (Get-Date).AddDays(-30)
    Get-DomainComputer -Server $Server | ? {$_.pwdlastset -lt $Date} | Select-Object SamAccountName, pwdlastset | ConvertTo-Csv -NoTypeInformation | Out-File ".\Domain_Computers_Pwd_Not_Rotated_${ProjectSuffix}.csv";

    # Domain Users with admin rights
    Get-DomainUser -AdminCount -Server $Server | Select-Object -exp SamAccountName | Out-File ".\Domain_Users_Admin_Rights_${ProjectSuffix}.log";

    # Admin accounts that are missing delegation restrictions
    Get-DomainUser -AllowDelegation -Server $Server | ?{$_.memberof -match 'Domain Admins'}| Select-Object SamAccountName | Out-File ".\Domain_Admins_Missing_Delegation_Restrictions_${ProjectSuffix}.log"

    # Domain Users with Passwords that do not expire
    Get-AdUser -filter { passwordNeverExpires -eq $true -and enabled -eq $true } -Server $Server | Select-Object -exp SamAccountName | Out-File ".\Domain_Users_PwdNeverExpires_${ProjectSuffix}.log"

    # Domain Computers that do not use LAPS
    Get-ADComputer -Filter {ms-Mcs-AdmPwd -notlike "*"} -Server $Server | Select-Object -Property SamAccountname, DNSHostname, IPv4Address | ConvertTo-CSV -NoTypeInformation | Out-File ".\Domain_Computers_LAPS_Not_Installed_${ProjectSuffix}.csv"

    # Privileged Account in Protected Users Group
    Get-DomainUser -AdminCount -Server $Server | ? { $_.memberof -notmatch "Protected Users" } | Select-Object -exp SamAccountName | Out-File ".\Unprotected_Privileged_Accounts_${ProjectSuffix}.log";

    # Get all enabled Windows 7 that have been in use within the last 30 days
    $date = (Get-Date).AddDays(-30)
    Get-ADComputer -Filter 'operatingsystem -like "*windows 7*" -and enabled -eq "true" -and (Lastlogondate -GT $date)' -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address,Lastlogondate -Server $Server -Verbose | Select-Object -Property Name,Operatingsystem,OperatingSystemVersion,IPv4Address,lastlogondate | ConvertTo-Csv -NoTypeInformation | Out-File ".\Domain_Computers_Windows_7_${ProjectSuffix}.csv"

    # Get all enabled Windows 2008 Servers that have been in use within the last 30 days
    $date = (Get-Date).AddDays(-30)
    Get-ADComputer -Filter 'operatingsystem -like "*2008*" -and enabled -eq "true" -and (Lastlogondate -GT $date)' -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address,Lastlogondate -Server $Server -Verbose | Select-Object -Property Name,Operatingsystem,OperatingSystemVersion,IPv4Address,lastlogondate | ConvertTo-Csv -NoTypeInformation | Out-File ".\Domain_Computers_Windows_Server_2008_${ProjectSuffix}.csv"

    # Get all unsupported Windows 10 systems that have been in use within the last 30 days
    $date = (Get-Date).AddDays(-30)
    Get-ADComputer -Filter 'operatingsystem -like "*windows 10*" -and enabled -eq "true" -and (Lastlogondate -GT $date) -and (operatingsystemversion -like "*10586*" -or operatingsystemversion -like "*15063*" -or operatingsystemversion -like "*16299*" -or operatingsystemversion -like "*17134*" -or operatingsystemversion -like "*18362*" -or operatingsystemversion -like "*19041*" -or operatingsystemversion -like "*18363*" -or operatingsystemversion -like "*19043*")' -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address,Lastlogondate -Server $Server -Verbose | Select-Object -Property Name,Operatingsystem,OperatingSystemVersion,IPv4Address,lastlogondate | ConvertTo-Csv -NoTypeInformation | Out-File ".\Domain_Computers_Unsupported_Windows_10_${ProjectSuffix}.csv"
}

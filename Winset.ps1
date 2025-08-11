<#
.SYNOPSIS
Windows System Enumeration Tool (Winset) for penetration testing and system audits.

.DESCRIPTION
This script collects comprehensive system information and outputs an HTML report, as well as CSV and JSON outputs.

.PARAMETER OutputFile
Path to save the report. Default is C:\temp\ (file names: system_report.html, system_report.csv, system_report.json)

.PARAMETER Full
Run all checks including extended file searches (takes longer)

.EXAMPLE
.\Winset.ps1
Run standard checks with default output location and report name (C:\temp\)

.EXAMPLE
.\Winset.ps1 -Full
Run all checks including extended searches

.EXAMPLE
.\Winset.ps1 -Output "D:\reports\audit"
Run default checks and export results with a custom name and path. Please note that extensions will be added automatically.

.LINK
https://github.com/weissec/Winset/

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$Output = "C:\temp\winset_report",
    
    [Parameter(Mandatory=$false)]
    [switch]$Full
)

# Ensure output directory exists
$outputDir = Split-Path -Parent $Output
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Set Output File Names
$OutputFile = $($Output + ".html")
$OutputFileJSON = $($Output + ".json")
$OutputFileCSV = $($Output + ".csv")

# Initialize executed checks counter
$script:executedChecks = 0

# Initialize results array for JSON and CSV export
$script:results = @()

function Export-JsonReport {
    try {
        $report = @{
            SystemInfo = @{
                Hostname = hostname
                OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
                User = whoami
                IsAdmin = $isadmin
                ExecutionTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }
            Checks = $script:results
            Summary = @{
                TotalChecks = $script:executedChecks
                SuccessfulChecks = ($script:results | Where-Object { $_.Status -eq 'Success' }).Count
                FailedChecks = ($script:results | Where-Object { $_.Status -eq 'Failed' }).Count
            }
        }
        
        $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFileJSON -Force
    } catch {
        Write-Host "[!] Error generating JSON report: $_" -ForegroundColor Red
    }
}

function Export-CsvReport {
    try {
        # Prepare CSV-friendly data
        $csvData = $script:results | Select-Object @(
            'Category',
            'Check',
            'Status',
			'Timestamp',
			'Severity',
            @{Name='Output';Expression={$_.Output -replace "`r`n"," | " -replace "`n"," | "}}
        )
        
        $csvData | Export-Csv -Path $OutputFileCSV -NoTypeInformation -Force
    } catch {
        Write-Host "[!] Error generating CSV report: $_" -ForegroundColor Red
    }
}

# Error Logs
$ErrorActionPreference = "Stop"
$ErrorLogFile = Join-Path (Split-Path $OutputFile -Parent) "winset_errors.log"

function Log-Error {
    param (
        [string]$Message,
        [string]$Command
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $errorEntry = "[$timestamp] Error executing '$Command': $Message`n"
    Add-Content -Path $ErrorLogFile -Value $errorEntry
    Write-Host -ForegroundColor Red $errorEntry
}

# Required for some commands to work
Add-Type -AssemblyName System.Web
Write-Host -fore green " _ _ _ _ ___ _ _____ _____ _____ "
Write-Host -fore green "| | | | |   | |  ___|  ___|_   _|"
Write-Host -fore green "| | | | | | | |___  |  ___| | |  "
Write-Host -fore green "|_____|_|_|___|_____|_____| |_| " 
Write-Host -fore green "`nWindows System Enumeration Tool (v.0.3)"

read-host "`nPress ENTER to start the scan or CTRL + C to exit"
Write-Host "[+] Checking local host, please wait.."

# Define action groups with system commands to execute

$system_actions = @{
	'System Info' = @{ Command = { systeminfo }; Severity = 'Info' }
    # Another fallback OS version: (Get-WmiObject -Class Win32_OperatingSystem).Caption
	'Operating System Version' = @{ Command = { Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\" | Format-List }; Severity = 'Info' }
    'Environment Variables' = @{ Command = { Get-ChildItem Env: }; Severity = 'Info' }
	'PowerShell Execution Policy' = @{ Command = { Get-ExecutionPolicy -List}; Severity = 'Medium' }
	'Searching for SAM backup files' = @{ Command = {
        $paths = @(
            "$env:SYSTEMROOT\repair\SAM",
            "$env:SYSTEMROOT\system32\config\regback\SAM"
        )

        foreach ($path in $paths) {
            [PSCustomObject]@{
                Path    = $path
                Exists  = Test-Path $path
            }
        }
    }; Severity = 'High' }
    'Running Processes' = @{ Command = { gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} }; Severity = 'Info' }
    'Installed Software Directories' = @{ Command = { Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | Select-Object Parent,Name,LastWriteTime }; Severity = 'Info' }
    'Software in Registry' = @{ Command = { Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | Select-Object Name }; Severity = 'Info' }
	'Scheduled Tasks' = @{ Command = { Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | Select-Object TaskName,TaskPath,State }; Severity = 'Low' }
    'Automatic Startup Programs' = @{ Command = { Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User }; Severity = 'Info' }
	'List of Services' = @{ Command = { Get-WmiObject Win32_Service | Where-Object { $_.StartName -eq "LocalSystem" } | Select-Object Name, State, StartMode }; Severity = 'Info' }
	'Services Running as SYSTEM' = @{ Command = { Get-WmiObject Win32_Service | Where-Object { $_.StartName -eq "LocalSystem" } | Select-Object Name, State, StartMode }; Severity = 'Info' }
	'Windows Defender Status' = @{ Command = { Get-MpComputerStatus | fl }; Severity = 'Info' }
	'Antivirus Software in Use' = @{ Command = { wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayname | Select-Object -Skip 1 }; Severity = 'Info' }
	'Windows Hotfixes' = @{ Command = { Get-HotFix | select-object Hotfixid,description,installedon }; Severity = 'Info' }
	# Another fallback Hotfixes: Get-WmiObject -query "select * from win32_quickfixengineering" | foreach {$_.hotfixid}
	'Microsoft Edge Extensions' = @{ Command = { 
        $extensionsPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
        if (Test-Path $extensionsPath) {
            Get-ChildItem -Path $extensionsPath | ForEach-Object {
                $manifestPath = Join-Path $_.FullName "manifest.json"
                if (Test-Path $manifestPath) {
                    try {
                        $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
                        [PSCustomObject]@{
                            Name        = $manifest.name
                            Description = $manifest.description
                            Version     = $manifest.version
                            ID          = $_.Name
                        }
                    } catch {
                        Write-Warning "Failed to parse manifest for extension ID $($_.Name)"
                    }
                }
            }
        } else {
            Write-Warning "Edge extensions path not found."
        }
    }; Severity = 'Low' }
}

$user_actions = @{
    'Current User' = @{ Command = { whoami }; Severity = 'Info' }
    'User Domain' = @{ Command = { $env:USERDOMAIN }; Severity = 'Info' }
    'User Profile Path' = @{ Command = { $env:USERPROFILE }; Severity = 'Info' }
	'Local Users' = @{ Command = { Get-LocalUser | Select-Object Name,Enabled,LastLogon }; Severity = 'Info' }
	'Active User Sessions' = @{ Command = { query user /server:$env:COMPUTERNAME 2>&1 | Out-String }; Severity = 'Info' }
    # Another Active Sessions: get-wmiobject -Class Win32_Computersystem | select Username
    'Credential Manager' = @{ Command = { cmdkey /list | Out-String }; Severity = 'Low' }
	'Stored Windows Credentials' = @{ Command = { vaultcmd /listcreds:"Windows Credentials" /all }; Severity = 'Low' }
    'User Autologon Registry Items' = @{ Command = { Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | Select-Object }; Severity = 'Low' }
    'Local Groups' = @{ Command = { Get-LocalGroup | Select-Object Name }; Severity = 'Info' }
    'Local Administrators' = @{ Command = { Get-LocalGroupMember Administrators | Select-Object Name, PrincipalSource }; Severity = 'Info' }
    'User Directories' = @{ Command = { Get-ChildItem C:\Users | Select-Object Name }; Severity = 'Info' }
	'Users SIDs' = @{ Command = { Get-WmiObject -Class Win32_UserAccount }; Severity = 'Info' }
	'Local Password Policy' = @{ Command = { net accounts }; Severity = 'Info' }
	'Orphaned User Accounts' = @{ Command = { Get-LocalUser | Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-90) }}; Severity = 'Medium' }
	'Kerberos Tickets' = @{ Command = { klist }; Severity = 'Low' }
	'Password Never Expires Accounts' = @{ Command = { 
    Get-LocalUser | Where-Object { $_.PasswordNeverExpires -eq $true } | 
    Select-Object Name, Enabled, LastLogon, PasswordNeverExpires
	}; Severity = 'Medium' }
}

$priviliges_actions = @{
	'User Privileges' = @{ Command = { whoami /priv }; Severity = 'Info' }
    'Folders with Everyone Permissions' = @{ Command = { Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} }; Severity = 'Low' }
    'Folders with BUILTIN\User Permissions' = @{ Command = { Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} }; Severity = 'Low' }
    'AlwaysInstallElevated Registry Setting' = @{ Command = { Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" }; Severity = 'High' }
	'User Account Control (UAC) Settings' = @{ Command = { Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object -Property ConsentPromptBehaviorAdmin, EnableLUA }; Severity = 'Medium' }
	'SAM Registry Key Permissions' = @{ Command = { Get-Acl -Path "HKLM:\SAM" }; Severity = 'Info' }
	'SYSTEM Registry Key Permissions' = @{ Command = { Get-Acl -Path "HKLM:\SYSTEM" }; Severity = 'Info' }
	'Main Folders Permissions' = @{ Command = { Get-Acl -Path "C:\", "C:\Program Files\*", "C:\Program Files (x86)\*", "C:\ProgramData\" }; Severity = 'Info' }
	# Add check for writeable service binaries here
	'Unquoted Service Paths' = @{ Command = { 
    $services = Get-CimInstance -ClassName Win32_Service -Property Name, PathName, StartMode
    $services | Where-Object { 
        $_.PathName -and
        $_.PathName -notmatch '^[''"]' -and
        $_.PathName -match '\s' -and
        $_.PathName -notlike '*C:\Windows*'
    } | 
    Select-Object Name, StartMode, PathName |
    Sort-Object PathName
	}; Severity = 'Info' }
	'PowerShell Module Auto-Loading' = @{ Command = { 
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "DisableAutoConfigSource" -ErrorAction SilentlyContinue | Out-String
	}; Severity = 'High' }
}

# Only run if part of a domain
$domain_actions = @{
	'Domain Name' = @{ Command = { wmic computersystem get domain }; Severity = 'Info' }
	'Domain Password Policy' = @{ Command = { net accounts /domain }; Severity = 'Info' }
	'Domain Admins' = @{ Command = { net group "Domain Admins" /domain }; Severity = 'Info' }
	'Domain Computers' = @{ Command = { net group "domain computers" /domain }; Severity = 'Info' }
	'Domain Controllers' = @{ Command = { net group "Domain Controllers" /domain }; Severity = 'Info' }
	'GPO Settings' = @{ Command = { gpresult /r }; Severity = 'Info' }
	# 'Domain Computers' = @{ Command = { dsquery computer }; Severity = 'Info' }
	# 'Domain Servers' = @{ Command = { net view /domain }; Severity = 'Info' }
	# 'Domain Controllers' = @{ Command = { nltest /dclist:<DOMAIN> }; Severity = 'Info' }
}

$azuread_actions = @{
    'Azure AD Join Status' = @{ Command = { dsregcmd /status }; Severity = 'Info' }
    'Azure AD Device ID' = @{ Command = { (dsregcmd /status | Select-String "DeviceId" | Out-String) }; Severity = 'Info' }
    'Azure AD Tenant Info' = @{ Command = { (dsregcmd /status | Select-String "TenantName" | Out-String) }; Severity = 'Info' }
    'Azure AD User Info' = @{ Command = { (dsregcmd /status | Select-String "Executing Account Name" | Out-String) }; Severity = 'Info' }
	'Azure AD Connect Status' = @{ Command = { 
		if (Get-Service -Name 'AzureADConnect' -ErrorAction SilentlyContinue) {
			Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect\*" | Out-String
		} else { "Azure AD Connect not installed" }
	}; Severity = 'Info' }
}

$network_actions = @{
    'Network Adapters' = @{ Command = { Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress }; Severity = 'Info' }
    'IP Configuration' = @{ Command = { Get-NetIPAddress }; Severity = 'Info' }
	'Network Information' = @{ Command = { Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,IPv4Address }; Severity = 'Info' }
	'DNS Servers' = @{ Command = { Get-DnsClientServerAddress -AddressFamily IPv4 }; Severity = 'Info' }
	# Another DNS Cache: ipconfig /displaydns
	'DNS Cache' = @{ Command = {  Get-DnsClientCache | Select-Object Entry, Name, Data | Format-Table -AutoSize | Out-String }; Severity = 'Low' }
	'ARP cache' = @{ Command = { Get-NetNeighbor -AddressFamily IPv4 | Select-Object ifIndex,IPAddress,LinkLayerAddress,State }; Severity = 'Info' }
	'Routing Table' = @{ Command = { Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,RouteMetric,ifIndex }; Severity = 'Info' }
	'Network Connections' = @{ Command = { netstat -ano }; Severity = 'Info' }
	'Open Ports' = @{ Command = { Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State, OwningProcess }; Severity = 'Low' }
	'Processes With Listening Ports' = @{ Command = { Get-Process -Id (Get-NetTCPConnection).OwningProcess | Select-Object ProcessName, Id }; Severity = 'Low' }
    'Firewall Rules' = @{ Command = { Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action }; Severity = 'Info' }
	'Wi-Fi Networks' = @{ Command = { netsh wlan show profile }; Severity = 'Info' } # Can use netsh wlan show profile name="ProfileName" key=clear to show passwords
	'Wi-Fi Passwords' = @{ Command = { $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[1].Trim()
    }

    foreach ($profile in $profiles) {
        $details = netsh wlan show profile name="$profile" key=clear
        $passwordLine = $details | Select-String "Key Content"
        $password = if ($passwordLine) { ($passwordLine -split ":")[1].Trim() } else { "[No password found]" }

        [PSCustomObject]@{
            SSID     = $profile
            Password = $password
        }
    }
}; Severity = 'Low' } 
	'IPv6 Configuration' = @{ Command = { Get-NetIPConfiguration | Where-Object { $_.IPv6DefaultGateway -ne $null } }; Severity = 'Info' }
	'Hosts File' = @{ Command = { Get-Content C:\WINDOWS\System32\drivers\etc\hosts }; Severity = 'Info' }
	'Firewall Disabled Rules' = @{ Command = { Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'False' } | Select-Object DisplayName, Profile, Direction, Action }; Severity = 'Low' }
}

$storage_actions = @{
	'Connected Drives' = @{ Command = { Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"} }; Severity = 'Info' }
	'Local Shares' = @{ Command = { net share }; Severity = 'Info' }
}

$extended_actions = @{
	'Unattend and Sysprep files' = @{ Command = { Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")} }; Severity = 'Medium' }
	'Web.config files' = @{ Command = { Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue }; Severity = 'Low' }
	'Other interesting files' = @{ Command = { Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue }; Severity = 'Medium' }
	'Various config files' = @{ Command = { Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue }; Severity = 'Low' }
	'Word password in HKLM' = @{ Command = { reg query HKLM /f password /t REG_SZ /s }; Severity = 'Medium' }
	'Word password in HKCU' = @{ Command = { reg query HKCU /f password /t REG_SZ /s }; Severity = 'Medium' }
	'Files containing word "password"' = @{ Command = { Get-ChildItem c:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*"}| Select-String -Pattern "password" }; Severity = 'Low' }
}

$admin_actions = @{
	'BitLocker Status' = @{ Command = { Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionMethod }; Severity = 'Medium' }
	'Windows Defender Exclusions' = @{ Command = { Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath }; Severity = 'High' }
	'Shadow Copies Enumeration' = @{ Command = { vssadmin list shadows }; Severity = 'Medium' }
	'Audit Policy' = @{ Command = { auditpol /get /category:* }; Severity = 'Info' }
	'SAM File Permissions' = @{ Command = { Get-Acl -Path "C:\Windows\System32\config\SAM" }; Severity = 'Info' }
	'Potential DLL Hijacking' = @{ Command = { Get-ChildItem -Path "C:\Program Files" -Recurse -Include *.dll | ForEach-Object { Get-Acl $_.FullName } | Where-Object { $_.AccessToString -like "*Everyone*" } }; Severity = 'High' }
	'Windows Features Enabled' = @{ Command = { 
    Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | 
    Select-Object FeatureName,State
	}; Severity = 'Info' }
	'Windows Subsystem for Linux (WSL)' = @{ Command = {  Get-WindowsOptionalFeature -Online -FeatureName *Linux* | Select-Object FeatureName,State | Out-String }; Severity = 'Low' }
	'Event Log Configurations' = @{ Command = { 
    Get-WinEvent -ListLog * | 
    Where-Object { $_.IsEnabled -eq $true } | 
    Select-Object LogName, IsEnabled, MaximumSizeInBytes, RecordCount | Format-Table -AutoSize | Out-String
	}; Severity = 'Low' }
	'Security Events (Last 24h)' = @{ Command = { 
		$startTime = (Get-Date).AddDays(-1)
		$filter = @{
			LogName   = 'Security'
			StartTime = $startTime
		}

		try {
			Get-WinEvent -FilterHashtable $filter -MaxEvents 200 | Select-Object TimeCreated, Id, LevelDisplayName, Message
		} catch {
			Write-Warning "Unable to retrieve security events: $_"
		}
	}; Severity = 'Medium' }
}
# End actions

# Ensure output directory exists
$outputDir = Split-Path -Parent $OutputFile
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Create or clear the output file
New-Item -Path $OutputFile -ItemType File -Force | Out-Null

# Function to write HTML Report navigation for each action
function Prepare-Actions {
    param (
        $ActionsGroup,
        [string]$FilePath
    )
    foreach ($actionName in $ActionsGroup.Keys) {
        $sanitizedId = ($actionName -replace '[^a-zA-Z0-9]','').ToLower()
        Add-Content -Path $FilePath -Value "<a class='nav-item' data='$sanitizedId' href='#'>$actionName</a>"
    }
}

# Function to run actions and capture results
function Run-Actions {
    param (
        $ActionsGroup,
        [string]$FilePath
    )
    foreach ($actionName in $ActionsGroup.Keys) {

        $action = $ActionsGroup[$actionName]  # Get the entire action object
        $command = $action.Command            # Extract the command
        $severity = $action.Severity          # Extract the severity
        $sanitizedId = ($actionName -replace '[^a-zA-Z0-9]','').ToLower()  # Create a sanitized ID for HTML navigation
        
        try {
            Write-Host "[-] Checking: $actionName"
            $output = & $command | Out-String
			
			# Record results
            $script:executedChecks++
            
            # Store results for JSON/CSV output
            $script:results += [PSCustomObject]@{
                Category = $ActionsGroupName
                Check    = $actionName
                Command  = if ($command -is [scriptblock]) { $command.ToString() } else { $command }
                Output   = $output
                Status   = "Success"
				Severity = $severity
				Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }
			$script:results += $result
            
			$severityClass = "severity-$($action.Severity.ToLower())"
			$isEmptyResult = [string]::IsNullOrWhiteSpace($output) -or $output -match "^\s*$"
            $emptyNote = if ($isEmptyResult) { "<span class='status-note'><i><b>Note:</b> No results returned - as the check seemed to run successfully, this may simply indicate that nothing was found.</i></span>" } else { "" }
			
            Add-Content -Path $FilePath -Value @"
<div id="$sanitizedId" class="report-section">
    <div class="right-content">
		<div class="action-title-status">
			<h2>$actionName <span class="badge $severityClass">$severity</span></h2>
			<div class="statusdiv"><span class="status">Status: </span><span class="status-ok">Successfully Checked</span></div>
		</div>
		$emptyNote
        <pre>$([System.Web.HttpUtility]::HtmlEncode($output))</pre>
    </div>
</div>
"@
        } catch {
            $script:executedChecks++
            $errorMsg = $_.Exception.Message
            
            # Store results for JSON/CSV output
            $script:results += [PSCustomObject]@{
                Category = $ActionsGroupName
                Check    = $actionName
                Command  = if ($command -is [scriptblock]) { $command.ToString() } else { $command }
                Output   = $errorMsg
                Status   = "Failed"
				Severity = $action.Severity
				Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }
			$script:results += $result
            
			$severityClass = "severity-$($action.Severity.ToLower())"
			
            Add-Content -Path $OutputFile -Value @"
<div id="$sanitizedId" class="report-section">
    <div class="right-content">
		<div class="action-title-status">
			<h2>$actionName <span class="badge $severityClass">$severity</span></h2>
			<div class="statusdiv"><span class="status">Status: </span><span class="status-failed">Check Failed</span></div>
		</div>
        <pre>$([System.Web.HttpUtility]::HtmlEncode($output))</pre>
    </div>
</div>
"@
        }
    }
}

# Check if running PowerShell as Administrator
[bool] $isadmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# HTML REPORT Start
Add-Content -Path $OutputFile -Value @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Winset - System Report</title>
	<style>
    :root {
        --primary: #4a6fa5;
        --secondary: #166088;
        --accent: #4fc3f7;
        --dark: #1a2639;
        --light: #f0f4f8;
		--box: #e7eef2;
        --danger: #e63946;
        --warning: #ffaa00;
        --success: #2ecc71;
        --text-light: rgba(255,255,255,0.8);
        --border-light: rgba(255,255,255,0.1);
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    body {
        background-color: #f5f7fa;
        color: #333;
        line-height: 1.6;
    }
    
    .container {
        display: flex;
        min-height: 100vh;
    }
    
    /* Sidebar Styles */
    .sidebar {
        width: 350px;
        background: var(--dark);
        color: white;
        padding: 20px 0;
        height: 100vh;
        overflow-y: auto;
        position: sticky;
        top: 0;
        box-shadow: 2px 0 10px rgba(0,0,0,0.1);
    }
    
    .sidebar-header {
        padding: 0 20px 20px;
        border-bottom: 1px solid var(--border-light);
        margin-bottom: 20px;
    }
    
    .sidebar-header h2 {
        color: var(--accent);
        font-weight: 300;
        margin-bottom: 5px;
    }
    
    .sidebar-header p {
        font-size: 0.9rem;
        opacity: 0.8;
    }
	
	/* Summary Section Styles */
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }
    
    .summary-card {
        background: white;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    }
    
    .summary-card h3 {
        color: var(--secondary);
        margin-bottom: 15px;
        font-weight: 500;
        display: flex;
        align-items: center;
    }
    
    .info-item {
        display: flex;
        margin-bottom: 10px;
        line-height: 1.4;
    }
    
    .info-label {
        font-weight: 600;
        color: var(--dark);
        min-width: 120px;
    }
    
    .info-value {
        color: #555;
        word-break: break-word;
    }
		
	.main-content {
		flex: 1;
		padding: 30px;
		overflow-y: auto;
		width: calc(100% - 350px);
	}
    
    .right-content {
        width: 100%;
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
    }
    
    /* Font Awesome icons (optional) */
    .fas {
        font-family: 'Font Awesome 5 Free';
        font-weight: 900;
    }
    
    .nav-section {
        margin-bottom: 25px;
    }
    
    .nav-section h3 {
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        padding: 0 20px;
        margin: 15px 0;
        color: var(--accent);
        font-weight: 500;
    }
    
    .nav-item {
        display: block;
        padding: 8px 20px;
        color: var(--text-light);
        text-decoration: none;
        transition: all 0.3s ease;
        border-left: 3px solid transparent;
        font-size: 0.90rem;
    }
    
    .nav-item:hover, 
    .nav-item.active {
        background: rgba(255,255,255,0.05);
        color: white;
        border-left: 3px solid var(--accent);
    }
    
    .nav-item i {
        margin-right: 10px;
        width: 20px;
        text-align: center;
    }
    
    /* Main Content Styles */
    .main-content {
        flex: 1;
        padding: 30px;
        overflow-y: auto;
    }
    
    .report-section {
        padding: 25px;
        margin-bottom: 30px;
        display: none;
        animation: fadeIn 0.3s ease-out forwards;
    }
    
    #info.report-section{
		display: block;
	}
	
    .report-section.active {
        display: block;
    }
    
    .report-section h2 {
        color: var(--secondary);
        margin-bottom: 20px;
        font-weight: 400;
        font-size: 1.5rem;
    }
	
	 /* Status Badges */
    .status-ok {
        background-color: #28a745;
        color: white;
		border-radius: 0px 4px 4px 0px;
        font-size: 0.9em;
		color: white;
		display: inline-block;
		text-align: right;
        font-weight: 500;
		margin-bottom: 15px;
		padding: 4px 8px;
    }
    
    .status-failed {
        background-color: #dc3545;
        color: white;
		border-radius: 0px 4px 4px 0px;
        font-size: 0.9em;
		color: white;
		display: inline-block;
		text-align: right;
        font-weight: 500;
		margin-bottom: 15px;
		padding: 4px 8px;
    }
    
    .status-note {
        color: #6c757d;
        font-size: 0.9em;
		display: block;
        margin-bottom: 15px;
    }
    
    .status {
        margin-bottom: 15px;
		display: inline-block;
		padding: 4px 8px;
        border-radius: 4px 0px 0px 4px;
        font-size: 0.9rem;
        font-weight: 500;
		background-color: #d9d9d9;
    }
	
	.action-title-status {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	
	action-title-status.h2 {
		flex: 1;
		display: block;
	}
	
	.statusdiv {
		flex: 2;
		text-align: right;
	}
    
    pre {
        background: var(--box);
        padding: 20px;
        border-radius: 6px;
        overflow-x: auto;
        font-family: 'Consolas', monospace;
        font-size: 0.9rem;
        line-height: 1.5;
        white-space: pre-wrap;
        word-wrap: break-word;
        border-left: 4px solid var(--accent);
    }
    
    /* Utility Classes */
    .text-error { color: var(--danger); }
    .text-warning { color: var(--warning); }
    .text-success { color: var(--success); }
    .text-link { color: var(--primary); text-decoration: underline; }
    
    .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 500;
        color: white;
    }
    
    .badge-admin { background: var(--success); }
    .badge-user { background: var(--warning); }
    .badge-domain { background: var(--primary); }
    .badge-workgroup { background: #6c757d; }
	
	/* Severity Badges */
    .severity-critical {
        background-color: #A13FA0;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8em;
        margin-left: 10px;
    }
    
    .severity-high {
        background-color: #dc3545;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8em;
        margin-left: 10px;
    }
    
    .severity-medium {
        background-color: #fd7e14;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8em;
        margin-left: 10px;
    }
    
    .severity-low {
        background-color: #28a745;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8em;
        margin-left: 10px;
    }
	
	.severity-info {
        background-color: #6BD2E3;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8em;
        margin-left: 10px;
    }
    
    /* Responsive Design */
    @media (max-width: 768px) {
        .container {
            flex-direction: column;
        }
        
        .sidebar {
            width: 100%;
            height: auto;
            position: relative;
        }
        
        .main-content {
            padding: 20px;
        }
    }
    
    /* Animations */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
</style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <div class="sidebar-header">
                <h2>Winset Report</h2>
                <p>Windows System Enumeration Tool</p>
            </div>
            
            <a class="nav-item active" data="info" href="#">&#128203; Report Summary</a>
"@

# If Admin, let user know about additional checks
if ($isadmin -eq $true) {
	Write-Host -fore green '[i] Administrative Priviliges Detected: Adding additional checks..'
} else {
	Write-Host -fore yellow '[i] Standard User Privileges Detected: Skipping administrative checks..'
}

# Determine domain, Workgroup or Azure AD join status
$cs = Get-WmiObject -Class Win32_ComputerSystem
$dsreg = dsregcmd /status

if ($cs.PartOfDomain -eq $true -and $cs.Domain -notmatch "onmicrosoft.com") {
    Write-Host -fore blue '[i] Host is part of an on-premises Domain: Adding Domain checks..'
    [bool]$addomain = $true
    [bool]$azuread = $false
}
elseif ($dsreg -match "AzureAdJoined\s*:\s*YES") {
    Write-Host -fore blue '[i] Host is Azure AD joined: Adding AzureAD checks..'
    [bool]$addomain = $false
    [bool]$azuread = $true
}
else {
    Write-Host -fore blue '[i] Host is part of a Workgroup: Skipping domain-related checks..'
    [bool]$addomain = $false
    [bool]$azuread = $false
}

# Prepare Actions HTML report
Add-Content -Path $OutputFile -Value "<div class='nav-section'><h3>&#128187; System Information:</h3>" # System
Prepare-Actions -ActionsGroup $system_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#128100; Users&#47;Accounts:</h3>" # Accounts
Prepare-Actions -ActionsGroup $user_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#128273; User Privileges:</h3>" # Local Priviliges
Prepare-Actions -ActionsGroup $priviliges_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#127760; Network Settings:</h3>" # Network
Prepare-Actions -ActionsGroup $network_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#128189; Storage Devices:</h3>" # Storage
Prepare-Actions -ActionsGroup $storage_actions -FilePath $OutputFile

if ($azuread -eq $true) {
    Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#9729; Azure AD Information:</h3>"
    Prepare-Actions -ActionsGroup $azuread_actions -FilePath $OutputFile
} # Only add AzureAD section if detected

if ($addomain -eq $true) {
	Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#127970; Domain Information:</h3>" # Domain
	Prepare-Actions -ActionsGroup $domain_actions -FilePath $OutputFile	
} # Only add domain section if AD detected

if ($isadmin -eq $true) {
	Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#128274; Privileged Checks:</h3>" # Admin
	Prepare-Actions -ActionsGroup $admin_actions -FilePath $OutputFile	
} # Only add admin section if running as admin

if ($Full) {
	Add-Content -Path $OutputFile -Value "</div><div class='nav-section'><h3>&#128269; Interesting Files:</h3>" # Interesting Files
    Prepare-Actions -ActionsGroup $extended_actions -FilePath $OutputFile
} # Conditionally prepare optional actions (full parameter)

Add-Content -Path $OutputFile -Value "</div></div><div class='main-content'>"

# Report details section:
Add-Content -Path $OutputFile -Value @"
<div id="info" class="report-section">
    <div class="right-content">
        <h2>Report Summary</h2>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3><i class="fas fa-desktop"></i> System Information</h3>
                <div class="info-item">
                    <span class="info-label">Date & Time:</span>
                    <span class="info-value">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Hostname:</span>
                    <span class="info-value">$(hostname)</span>
                </div>
                <div class="info-item">
                    <span class="info-label">OS Version:</span>
                    <span class="info-value">$((Get-WmiObject -Class Win32_OperatingSystem).Caption)</span>
                </div>
            </div>
            
            <div class="summary-card">
                <h3><i class="fas fa-user"></i> User Context</h3>
                <div class="info-item">
                    <span class="info-label">Run as User:</span>
                    <span class="info-value">$(whoami)</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Privileges:</span>
                    <span class="info-value">$(if ($isadmin) { '<span class="badge badge-admin">Administrator</span>' } else { '<span class="badge badge-user">Standard User</span>' })</span>
                </div>
            </div>
            
            <div class="summary-card">
                <h3><i class="fas fa-network-wired"></i> Domain Information</h3>
"@

# Domain information logic
if ($addomain -eq $true) {
    Add-Content -Path $OutputFile -Value @"
                <div class="info-item">
                    <span class="info-label">Domain:</span>
                    <span class="info-value"><span class="badge badge-domain">$(wmic computersystem get domain | Select-Object -Skip 1)</span></span>
                </div>
"@
} elseif ($azuread -eq $true) {
    $tenantLine = dsregcmd /status | Select-String "TenantName"
    $tenantName = ($tenantLine -split ":")[1].Trim()
    Add-Content -Path $OutputFile -Value @"
                <div class="info-item">
                    <span class="info-label">AzureAD Domain: </span>
                    <span class="info-value"><span class="badge badge-domain">$tenantName</span></span>
                </div>
"@
} else {
    Add-Content -Path $OutputFile -Value @"
                <div class="info-item">
                    <span class="info-label">Workgroup:</span>
                    <span class="info-value"><span class="badge badge-workgroup">WORKGROUP</span></span>
                </div>
"@
}

# This closes main-content, sidebar, and container
Add-Content -Path $OutputFile -Value "</div></div></div></div>"

# Run standard actions and print output
$script:ActionsGroupName = 'System Information'
Run-Actions -ActionsGroup $system_actions -FilePath $OutputFile

$script:ActionsGroupName = 'User Information'
Run-Actions -ActionsGroup $user_actions -FilePath $OutputFile

$script:ActionsGroupName = 'User Privileges'
Run-Actions -ActionsGroup $priviliges_actions -FilePath $OutputFile

$script:ActionsGroupName = 'Network Settings'
Run-Actions -ActionsGroup $network_actions -FilePath $OutputFile

$script:ActionsGroupName = 'Storage Devices'
Run-Actions -ActionsGroup $storage_actions -FilePath $OutputFile

if ($azuread -eq $true) {
	$script:ActionsGroupName = 'Azure AD Information'
    Run-Actions -ActionsGroup $azuread_actions -FilePath $OutputFile
} # Only run domain actions if Azure AD detected

if ($addomain -eq $true) {
	$script:ActionsGroupName = 'AD Domain Information'
	Run-Actions -ActionsGroup $domain_actions -FilePath $OutputFile
} # Only run domain actions if AD detected

if ($isadmin -eq $true) {
	$script:ActionsGroupName = 'Privileged Checks'
	Run-Actions -ActionsGroup $admin_actions -FilePath $OutputFile
} # Only run admin if administrator prompt

if ($Full) {
	$script:ActionsGroupName = 'Extended Checks'
    Run-Actions -ActionsGroup $extended_actions -FilePath $OutputFile
} # Include extended actions if -Full is specified

# End HTML Report
Add-Content -Path $OutputFile -Value @"
</div></div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    const navItems = document.querySelectorAll('.nav-item');
    const contentSections = document.querySelectorAll('.report-section');
    
    // Set first item as active by default
    navItems[0].classList.add('active');
    
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all items
            navItems.forEach(nav => nav.classList.remove('active'));
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Hide all content sections
            contentSections.forEach(section => {
                section.style.display = 'none';
            });
            
            // Show the target section
            const targetId = this.getAttribute('data');
            const targetSection = document.getElementById(targetId);
            if (targetSection) {
                targetSection.style.display = 'block';
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
    
    // Simple syntax highlighting
    const preElements = document.querySelectorAll('pre');
    preElements.forEach(pre => {
        const text = pre.textContent;
        let html = text
            .replace(/(error|failed|denied)/gi, '<span class="text-error">$1</span>')
            .replace(/(warning|caution)/gi, '<span class="text-warning">$1</span>')
            .replace(/(success|enabled|allowed)/gi, '<span class="text-success">$1</span>')
            .replace(/([A-Za-z]+:\/\/[^\s]+)/g, '<a href="$1" target="_blank" class="text-link">$1</a>');
        pre.innerHTML = html;
    });
});
</script>
</body>
</html>
"@

# Generate CSV and JSON Reports
Write-Host "[+] Generating reports.."
Export-JsonReport
Export-CsvReport

Write-Host -fore green "`n[i] Winset execution completed." 

# Summary output
$successCount = @($script:results | Where-Object { $_.Status -eq 'Success' }).Count
$failedCount = @($script:results | Where-Object { $_.Status -eq 'Failed' }).Count

# Ensure counts match total executed checks
if (($successCount + $failedCount) -ne $script:executedChecks) {
    # Reconcile any discrepancies
    $successCount = $script:executedChecks - $failedCount
}

Write-Host ""
Write-Host "[i] Execution Summary:"
Write-Host "[-] Total checks executed: $script:executedChecks"
Write-Host "[-] Successful checks: $successCount"
Write-Host "[-] Failed checks: $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { 'Red' } else { 'White' })

$critCount = ($script:results | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount = ($script:results | Where-Object { $_.Severity -eq 'High' }).Count
$mediumCount = ($script:results | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount = ($script:results | Where-Object { $_.Severity -eq 'Low' }).Count
$infoCount = ($script:results | Where-Object { $_.Severity -eq 'Info' }).Count

Write-Host "`n[!] Risk Summary:"
Write-Host "[-] Critical Risk Findings: $critCount" -ForegroundColor Magenta
Write-Host "[-] High Risk Findings: $highCount" -ForegroundColor Red
Write-Host "[-] Medium Risk Findings: $mediumCount" -ForegroundColor Yellow
Write-Host "[-] Low Risk Findings: $lowCount" -ForegroundColor Green
Write-Host "[-] Informational Findings: $infoCount" -ForegroundColor Cyan

Write-Host "`n[i] Report Files:"
Write-Host "[-] HTML report generated: $OutputFile"
Write-Host "[-] JSON report generated: $OutputFileJSON"
Write-Host "[-] CSV report generated: $OutputFileCSV"

if (Test-Path $ErrorLogFile) {
	Write-Host "[-] Errors encountered: $(Get-Content $ErrorLogFile | Measure-Object -Line).Lines" -ForegroundColor Red
	Write-Host "[-] Error log: $ErrorLogFile" -ForegroundColor Red
}

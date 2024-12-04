# Usage: .\Winset.ps1
# Specify Output Path: .\Winset.ps1 -OutputFile "D:\logs\report.html" (default: "C:\temp\winset-report.html")
# Run full checks (requires several minutes).\Winset.ps1 -Full
# (Full checks scan the system for interesting files or strings.)

# Parameters for script execution (must be first line)
param (
    [string]$OutputFile = "C:\temp\system_report.html",  # Default output file
    [switch]$Full # Include all actions if -Full is specified
)

# Required for some commands to work
Add-Type -AssemblyName System.Web

Write-Host -fore green "============= Winset v0.1 ============"
Write-Host -fore green "    Windows System Enumeration Tool"
Write-Host -fore green "======================================"
Write-Host "[+] Checking local host, please wait.."

# Define action groups with system commands to execute
$system_actions = @{
    'System Info' = 'systeminfo';
    #'OS Version' = '(Get-WmiObject -Class Win32_OperatingSystem).Caption';
	'Operating System Version' = 'Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\" | fl';
    'Environment Variables' = 'Get-ChildItem Env:';
	'PowerShell Execution Policy' = 'Get-ExecutionPolicy -List';
	'Searching for SAM backup files' = 'Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM';
    'Running Processes' = 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}}';
    'Installed Software Directories' = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | Select-Object Parent,Name,LastWriteTime';
    'Software in Registry' = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | Select-Object Name';
	'Scheduled Tasks' = 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | Select-Object TaskName,TaskPath,State';
    'Startup Commands' = 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User';
	'List of Services' = 'Get-WmiObject Win32_Service | Where-Object { $_.StartName -eq "LocalSystem" } | Select-Object Name, State, StartMode';
	'Services Running as SYSTEM' = 'Get-WmiObject Win32_Service | Where-Object { $_.StartName -eq "LocalSystem" } | Select-Object Name, State, StartMode';
	'Windows Defender Status' = 'Get-MpComputerStatus | fl';
	'Antivirus Software in Use' = 'wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayname | Select-Object -Skip 1'
	'Windows Hotfixes' = 'Get-HotFix | select-object Hotfixid,description,installedon';
	# Another Hotfixes in case: 'Get-WmiObject -query "select * from win32_quickfixengineering" | foreach {$_.hotfixid}';
}

$user_actions = @{
    'Current User' = 'whoami';
    'User Domain' = '$env:USERDOMAIN';
    'User Profile Path' = '$env:USERPROFILE';
	'Local Users' = 'Get-LocalUser | Select-Object Name,Enabled,LastLogon';
    'Logged in Users' = 'get-wmiobject -Class Win32_Computersystem | select Username';
    'Credential Manager' = 'cmdkey /list';
	'Stored Credentials' = 'vaultcmd /listcreds:"Windows Credentials" /all';
    'User Autologon Registry Items' = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | Select-Object';
    'Local Groups' = 'Get-LocalGroup | Select-Object Name';
    'Local Administrators' = 'Get-LocalGroupMember Administrators | Select-Object Name, PrincipalSource';
    'User Directories' = 'Get-ChildItem C:\Users | Select-Object Name';
	'Users SIDs' = 'Get-WmiObject -Class Win32_UserAccount';
	'Local Password Policy' = 'net accounts';
	'Orphaned User Accounts' = 'Get-LocalUser | Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-90) }';
	'Kerberos Tickets' = 'klist';
}

$priviliges_actions = @{
	'User Privileges' = 'whoami /priv';
    'Folders with Everyone Permissions' = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}}';
    'Folders with BUILTIN\User Permissions' = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}}';
    'AlwaysInstallElevated Registry Setting' = 'Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer"';
	'User Account Control (UAC) Settings' = 'Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object -Property ConsentPromptBehaviorAdmin, EnableLUA';
	'HKLM:\SAM Registry Key Permissions' = 'Get-Acl -Path "HKLM:\SAM"';
	'HKLM:\SYSTEM Registry Key Permissions' = 'Get-Acl -Path "HKLM:\SYSTEM"';
	'Main Folders Permissions' = 'Get-Acl -Path "C:\", "C:\Program Files\*", "C:\Program Files (x86)\*", "C:\ProgramData\"';
	'Potential DLL Hijacking' = 'Get-ChildItem -Path "C:\Program Files" -Recurse -Include *.dll | ForEach-Object { Get-Acl $_.FullName } | Where-Object { $_.AccessToString -like "*Everyone*" }';
	'Writeable Services' = 'Get-WmiObject Win32_Service | Where-Object { $_.StartName -like "*$env:USERNAME*" }';
	'Unquoted Service Paths' = @"
Get-WmiObject -Class Win32_Service -Property Name, PathName, StartMode | Where-Object { `$_`.PathName -notlike 'C:\Windows*' -and `$_`.PathName -notlike '\"*' } | Select-Object Name, StartMode, PathName
"@; # As this command contains ' and " we need to use the @" to get it to work
}

# Only run if part of a domain
$domain_actions = @{
	'Domain Name' = 'wmic computersystem get domain';
	'Domain Password Policy' = 'net accounts /domain';
	'Domain Admins' = 'net group "Domain Admins" /domain';
	'Domain Computers' = 'net group "domain computers" /domain';
	'Domain Controllers' = 'net group "Domain Controllers" /domain';
	'GPO Settings' = 'gpresult /r';
	# 'Domain Computers' = 'dsquery computer';
	# 'Domain Servers' = 'net view /domain';
	# 'Domain Controllers' = 'nltest /dclist:<DOMAIN>'
}

$network_actions = @{
    'Network Adapters' = 'Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress';
    'IP Configuration' = 'Get-NetIPAddress';
	'Network Information' = 'Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,IPv4Address';
	'DNS Servers' = 'Get-DnsClientServerAddress -AddressFamily IPv4';
	'DNS Cache' = 'ipconfig /displaydns';
	'ARP cache' = 'Get-NetNeighbor -AddressFamily IPv4 | Select-Object ifIndex,IPAddress,LinkLayerAddress,State';
	'Routing Table' = 'Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,RouteMetric,ifIndex';
	'Network Connections' = 'netstat -ano';
	'Open Ports' = 'Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State, OwningProcess';
	'Processes With Listening Ports' = 'Get-Process -Id (Get-NetTCPConnection).OwningProcess | Select-Object ProcessName, Id';
    'Firewall Rules' = 'Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action';
	'Wi-Fi Networks' = 'netsh wlan show profile'; # Can use netsh wlan show profile name="ProfileName" key=clear to show passwords
	'IPv6 Configuration' = 'Get-NetIPConfiguration | Where-Object { $_.IPv6DefaultGateway -ne $null }';
	'Hosts File' = 'Get-Content C:\WINDOWS\System32\drivers\etc\hosts';
}

$storage_actions = @{
	'Connected Drives' = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}';
	'Local Shares' = 'net share';
}

$extended_actions = @{
	'Unattend and Sysprep files' = 'Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}';
	'Web.config files' = 'Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue';
	'Other interesting files' = 'Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue';
	'Various config files' = 'Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue';
	'Word passwords in HKLM' = 'reg query HKLM /f password /t REG_SZ /s';
	'Word passwords in HKCU' = 'reg query HKCU /f password /t REG_SZ /s';
	'Files containing word "passwords"' = 'Get-ChildItem c:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*"}| Select-String -Pattern "password"';
}

# Add Section here to run if Administrator only
# Need to add an IF statement to catch this..

$admin_actions = @{
	'BitLocker Status' = 'Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionMethod';
	'Windows Defender Exclusions' = 'Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath';
	'Shadow Copies Enumeration' = 'vssadmin list shadows';
	'Audit Policy' = 'auditpol /get /category:*';
	'SAM File Permissions' = 'Get-Acl -Path "C:\Windows\System32\config\SAM"';
}

# Ensure output directory exists
$outputDir = Split-Path -Parent $OutputFile
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Create or clear the output file
New-Item -Path $OutputFile -ItemType File -Force | Out-Null

# Function to write HTML for each action
function Prepare-Actions {
    param (
        #[ordered]$ActionsGroup,
		$ActionsGroup,
        [string]$FilePath
    )
    foreach ($actionName in $ActionsGroup.Keys) {
		# Append the action name to the file
		Add-Content -Path $FilePath -Value "<a class='left-item' data='$actionName' href='#'>$actionName</a>"
    }
}

# Function to run actions and capture results
function Run-Actions {
    param (
        $ActionsGroup,
        [string]$FilePath
    )
    foreach ($actionName in $ActionsGroup.Keys) {
        $command = $ActionsGroup[$actionName]
		
        try {
			Write-Host "[-] Checking: $actionName"
            # Execute the command and capture output
            $output = Invoke-Expression $command 2>&1
			# Handle Different Output Formats
			if ($output -is [System.Array]) {
                $output = $output | Out-String # Join array elements
            } elseif ($output -is [PSCustomObject]) {
                $output = $output | Format-Table -AutoSize | Out-String  # Format custom objects
            } else {
                $output = $output | Out-String  # Default conversion to string
            }
            # Append results to the HTML report
			Add-Content -Path $FilePath -Value "<div id='$actionName' class='hide'><div class='right-content'><h1>$actionName</h1><pre>$([System.Web.HttpUtility]::HtmlEncode($output))</pre></div></div>"
        } catch {
            # Handle errors gracefully
			Add-Content -Path $FilePath -Value "<div id='$actionName' class='hide'><div class='right-content'><h1>$actionName</h1><pre>$([System.Web.HttpUtility]::HtmlEncode($_.Exception.Message))</pre></div></div>"
        }
    }
}

# If part of a Domain, run Domain actions
if ((gwmi win32_computersystem).partofdomain -eq $true) {
	write-host '[+] Host is part of a Domain: Adding Domain checks..'
	[bool] $addomain = $true
} else {
	write-host '[+] Host is part of a Workgroup: Removing Domain checks..'
	[bool] $addomain = $false
}

# Start HTML Report
Add-Content -Path $OutputFile -Value @"
<!doctypehtml><meta content='text/html; charset=utf-8'http-equiv=Content-Type><title>Winset - System Report</title><style>body{margin:0 auto;background:#1e2830;font-family:sans-serif;font-size:15px;height:100vh;}.siteheader{color:#fff;padding-left:20px;padding-right:20px;display:flex;justify-content:space-between;margin-bottom:0;vertical-align:center}.flexcontainer{display:flex;flex-direction:row}#left-panel{overflow-x:hidden;overflow-y:scroll;height:90vh;background:#1e2830;display:flex;flex-direction:column;align-self:flex-start;width:20%;min-width:250px}.linksection{color:#3cc792;padding-top:15px}.linksection h3{color:#fff;padding-left:15px}#links{flex:1}#right-panel{background:#3cc792;display:flex;flex-grow:1}.right-content{padding-left:60px;color:#1e2830;padding-top:30px;width:95%}.right-content h1{margin:0 auto;font-weight:100;padding-bottom:30px}.right-content pre{white-space:pre-wrap;background-color:#f2fffc;width:90%;padding:18px;overflow-x: hidden;max-height:60vh;}#top-title{padding-top:20px;color:#3cc792;align-self:center;text-align:center;padding-bottom:25px}#top-title h1{text-align:center;font-size:45px;margin-bottom:0;font-weight:100}.left-item{display:flex;align-self:auto;color:#3cc792;background:#363b40;padding-top:15px;padding-bottom:15px;cursor:pointer;text-decoration:none;width:100%;padding-left:20px;margin-bottom:2px}.left-item:hover,.select{background:#3cc792;color:#1e2830;font-weight:700}.general{font-weight:700;font-size:16px}.show{display:flex;width:100%}.hide{display:none}#info{margin:0 auto;width:100%}#info h1{font-weight:100}.tile{display:block;width:100%;padding-top:20px;padding-bottom:20px;margin-bottom:5px}.tile p{margin-top:0;margin-bottom:0}td{padding-right:50px}th{text-align:left;padding-bottom:10px;padding-right:100px}#info span{font-weight:bold;margin-right:50px;width:250px;display:inline-block}</style><div class=siteheader><h3>Windows System Enumeratio Tool (Winset) Report</h3><h4>Version: 1.0 (2024)</h4></div><div class=flexcontainer><div id=left-panel><div id=links><a class='left-item select'data=info href=#>Report Details</a>
"@

# Prepare standard actions
Add-Content -Path $OutputFile -Value "<div class='linksection'><h3>System Information:</h3>" # System
Prepare-Actions -ActionsGroup $system_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='linksection'><h3>Users&#47;Accounts:</h3>" # Accounts
Prepare-Actions -ActionsGroup $user_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='linksection'><h3>User Privileges:</h3>" # Local Priviliges
Prepare-Actions -ActionsGroup $priviliges_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='linksection'><h3>Network Settings:</h3>" # Network
Prepare-Actions -ActionsGroup $network_actions -FilePath $OutputFile
Add-Content -Path $OutputFile -Value "</div><div class='linksection'><h3>Storage Devices:</h3>" # Storage
Prepare-Actions -ActionsGroup $storage_actions -FilePath $OutputFile
if ($addomain -eq $true) {
	Add-Content -Path $OutputFile -Value "</div><div class='linksection'><h3>Domain Information:</h3>" # Domain
	Prepare-Actions -ActionsGroup $domain_actions -FilePath $OutputFile	
} # Only add domain section if AD detected

# Conditionally prepare optional actions (full parameter)
if ($Full) {
	Add-Content -Path $OutputFile -Value "<div class='linksection'><h3>Interesting Files:</h3>" # Interesting Files
    	Run-Actions -ActionsGroup $extended_actions -FilePath $OutputFile
}

Add-Content -Path $OutputFile -Value "</div></div></div><div id='right-panel'>"

# Add report details section
Add-Content -Path $OutputFile -Value '<div id="info" name="info" class="show"><div class="right-content"><h1>Report Information</h1>'
Add-Content -Path $OutputFile -Value "<pre><span>Date &amp; Time:</span>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</pre>"
Add-Content -Path $OutputFile -Value "<pre><span>Hostname:</span>$(hostname)</pre>"
Add-Content -Path $OutputFile -Value "<pre><span>Operating System:</span>$((Get-WmiObject -Class Win32_OperatingSystem).Caption)</pre>"
Add-Content -Path $OutputFile -Value "<pre><span>Run as User:</span>$(whoami)</pre>"
Add-Content -Path $OutputFile -Value "<pre><span>Domain:</span>$(wmic computersystem get domain | Select-Object -Skip 1)</pre></div></div>"

# Run standard actions and print output
Run-Actions -ActionsGroup $system_actions -FilePath $OutputFile
Run-Actions -ActionsGroup $user_actions -FilePath $OutputFile
Run-Actions -ActionsGroup $priviliges_actions -FilePath $OutputFile
Run-Actions -ActionsGroup $network_actions -FilePath $OutputFile
Run-Actions -ActionsGroup $storage_actions -FilePath $OutputFile
if ($addomain -eq $true) {
	Run-Actions -ActionsGroup $domain_actions -FilePath $OutputFile
} # Only run domain actions if AD detected

if ($Full) {
    Run-Actions -ActionsGroup $extended_actions -FilePath $OutputFile
} # Include extended actions if -Full is specified

# End HTML Report
Add-Content -Path $OutputFile -Value "</div></div></body><script>var ips=document.getElementsByClassName('left-item'),cch=document.getElementsByClassName('select');for(i=0;i<ips.length;i++)ips[i].addEventListener('click',function(){cch[0].classList.remove('select'),this.classList.toggle('select')});for(var showRightContent=function(){for(var e=document.getElementById('right-panel').childNodes,t=0;t<e.length;t++)e[t].className='hide';var s=this.getAttribute('data');document.getElementById(s).className='show'},i=0;i<ips.length;i++)ips[i].addEventListener('click',showRightContent,!1);var cca=document.getElementsByClassName('tool');for(i=0;i<cca.length;i++)cca[i].addEventListener('click',function(){this.classList.toggle('activetool');var e=this.nextElementSibling;'block'===e.style.display?e.style.display='none':e.style.display='block'});</script></html>"
Write-Host -fore green "======================================"
Write-Host "[+] Winset execution completed." 
Write-Host "[+] Report saved to: $OutputFile."

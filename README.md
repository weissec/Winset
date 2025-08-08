# Winset - Windows System Enumeration Tool

Simple script built in PoweShell and DOS to aid in Windows Build Reviews. 
Works on most Windows and Windows Server versions.

### PowerShell Version:
- Retrieves system details, user details and privileges, network information, storage details, interesting files and AD/AzureAD information.
- Results can be saved in the following formats: HTML, CSV, JSON (default: HTML).

#### Usage:
```
See help information: Get-Help .\Winset.ps1
Standard usage: .\Winset.ps1
Specify output file: .\Winset.ps1 -OutputFile "D:\logs\report.html" (default: "C:\temp\winset_report.html")
Specify different output format: .\Winset.ps1 -OutputFormat CSV
Run extended checks: .\Winset.ps1 -Full
```
> [!TIP]
> **Execution Policy:** when downloaded from Github directly, it is likely that the script will trigger an execution policy error (based on system settings). As a potential bypass, try copy the raw code from the script and paste in a newly created .PS1 file created on the target device.

### Batch Version:
- Retrieves the following:
System Information, Windows Patches, Network Shares, Local Groups, Local Admins, Local Users, Local Password Policies, Login Sessions, Group Policy settings, Potential clear-text Passwords, Scheduled tasks, Running processes, PowerShell execution policy, Disk Encryption status, List of Drives, List of potential insecure services (unquoted paths), List of third-party services, Permissions for third-party services, Potential clear-text passwords in Registry, Installed Software, Startup programs, Network configuration, Checks if connected to the internet, Routing table, Network services, Route to common destination, ARP table, Wi-Fi connections, General Domain information, Domain Password Policy, Domain Users, Domain Groups, Domain Controllers, Firewall Status, Firewall Configuration.
- All results are saved in separate TXT files.

Usage:
```
.\Winset.bat
```

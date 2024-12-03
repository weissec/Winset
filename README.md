# Winset - Windows System Enumeration Tool

Simple script built in PoweShell and DOS to aid in Windows Build Reviews. 
Works on most Windows and Windows Server versions.

#### PowerShell Version Main Functionalities:
- retrieves System, Users, Privileges, Network, Storage, Files, Domain information
- Results are included in an HTML Report

Usage:
```
Standard Usage: .\Winset.ps1
Specify Output File: .\Winset.ps1 -OutputFile "D:\logs\report.html" (default: "C:\temp\winset-report.html")
Run Extended Checks: .\Winset.ps1 -Full 
```

#### Batch Version Functionalities:
- Retrieves the following:
  System Information, Windows Patches, Network Shares, Local Groups, Local Admins, Local Users, Local Password Policies, Login Sessions, Group Policy settings, Potential clear-text Passwords, Scheduled tasks, Running processes, PowerShell execution policy, Disk Encryption status, List of Drives, List of potential insecure services (unquoted paths), List of third-party services, Permissions for third-party services, Potential clear-text passwords in Registry, Installed Software, Startup programs, Network configuration, Checks if connected to the internet, Routing table, Network services, Route to common destination, ARP table, Wi-Fi connections, General Domain information, Domain Password Policy, Domain Users, Domain Groups, Domain Controllers, Firewall Status, Firewall Configuration.
- All results are saved in separate TXT files.

Usage:
```
Standard Usage: .\Winset.bat
```

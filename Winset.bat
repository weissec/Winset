cls
@ECHO OFF
SETLOCAL enableextensions
TITLE Winset - Windows System Enumeration Tool

:: This script attempt to retrieve some useful information from the system and domain
ECHO ==================================================
ECHO      Winset - Windows System Enumeration Tool
ECHO ==================================================
ECHO This tool can be used to collect information from
ECHO a Windows system. For better results, please run
ECHO as Administrator. 

:: Check if running as admin
openfiles >nul 2>&1
if %ErrorLevel% NEQ 0 ( echo [i] Please run as Administrator for full results. )
ECHO.
PAUSE
SET runningpath=%~dp0
ECHO.
ECHO Starting enumeration for: %COMPUTERNAME%
ECHO Running as user: %USERNAME%
for /f "tokens=4-6 delims=. " %%g in ('ver') do set VERSION=%%g.%%h.%%i
echo Windows Version: %version%
ECHO.

MKDIR %runningpath%\Winset-Results
ECHO [+] Created folder "Winset-Results"
CD %runningpath%\Winset-Results
ECHO [+] Started [ %date% - %time% ]
ECHO.

ECHO [+] Running Local Checks..
:: Local Checks
systeminfo >> SystemInfo.txt
ECHO [Done] Retrieved System Information
wmic qfe list >> Windows-Patches.txt
ECHO [Done] Retrieved list of Windows Patches
net share >> Shares.txt
ECHO [Done] Retrieved list of Network Shares
net localgroup >> Local-Groups.txt
ECHO [Done] Retrieved list of Local Groups
net localgroup Administrators >> Local-Admins.txt
net users >> Local-Users.txt
ECHO [Done] Retrieved list of Local Users
net accounts >> Local-PW-Policies.txt
ECHO [Done] Retrieved Local Password Policies
cmdkey /list >> Login-Sessions.txt
ECHO [Done] Retrieved list of Login Sessions
GPResult /R >> Local-GP-Result.txt
ECHO [Done] Retrieved Group Policy settings
findstr /si password *.xml *.ini *.txt >> Local-Passwords.txt
findstr /spin "password" *.* >> Local-Passwords.txt
ECHO [Done] Retrieved list of potential clear-text passwords
schtasks /query /fo LIST /v >> Scheduled-Tasks.txt
ECHO [Done] Retrieved list of scheduled tasks
tasklist /SVC >> Processes.txt
ECHO [Done] Retrieved list of running processes
powershell Get-ExecutionPolicy >> Powershell-Policy.txt
ECHO [Done] Retrieved PowerShell execution policy
manage-bde -status >> BitLocker-Encryption-Status.txt
ECHO [Done] Retrieved Disk Encryption status
wmic logicaldisk get volumename,name >> Disks.txt

:: Insecure services / unquoted paths
wmic /OUTPUT:"Insecure-Services.txt" service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v '"'
ECHO [Done] Retrieved list of potential insecure services (unquoted paths)
for /f "tokens=2 delims='='" %%b in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do echo %%b | findstr "\\" >> Third-Party-Services.txt
ECHO [Done] Retrieved list of third party services
for /f eol^=^"^ delims^=^" %%a in (.\Third-Party-Services.txt) do cmd.exe /c icacls "%%a" >> Third-Party-Services-Permissions.txt 2>&1
ECHO [Done] Retrieved list of permissions for third party services

:: check for passwords in the registry
reg query HKLM /f password /t REG_SZ /s >> REG-Passwords.txt
reg query HKCU /f password /t REG_SZ /s >> REG-Passwords.txt
ECHO [Done] Retrieved list of potential clear-text passwords in Registry

:: Installed programs
wmic /output:"Software.txt" product get Name, Version, Vendor
ECHO [Done] Retrieved list of potential clear-text passwords
wmic startup get caption,command >> Startup.txt
ECHO [Done] Retrieved list of startup programs

:: Network Checks
ipconfig /all >> IPConfig.txt
ECHO [Done] Retrieved Network configuration
PING www.google.com >> InternetAccess.txt
ECHO [Done] Checked if connected to the internet
route PRINT >> Route.txt
ECHO [Done] Retrieved Routing table
netstat -ano >> Netstat.txt
ECHO [Done] Retrieved list of network services
tracert google.com >> Traceroute.txt
ECHO [Done] Retrieved route to common destination
arp -A >> ARP-Table.txt
ECHO [Done] Retrieved ARP table
netsh wlan show profile >> Wi-Fi-Connections.txt
ECHO [Done] Retrieved list of Wi-Fi connections

:: Domain Checks
net view /domain >> Domain-Info.txt
ECHO [Done] Retrieved Domain information
net accounts /domain >> Domain-PW-Policy.txt
ECHO [Done] Retrieved Domain Password Policy
net users /domain >> Domain-Users.txt
ECHO [Done] Retrieved list of Domain Users
net groups /domain >> Domain-Groups.txt
ECHO [Done] Retrieved list of Domain Groups
echo %logonserver% >> Main-Domain-Controller.txt
ECHO [Done] Retrieved Domain Controller Name

:: Firewall Checks
netsh firewall show state >> Firewall-State.txt
ECHO [Done] Retrieved Firewall Status
netsh firewall show config >> Firewall-Config.txt
ECHO [Done] Retrieved Firewall Configuration
ECHO.
ECHO [+] All Checks Completed [ %date% - %time% ]
ECHO.
ECHO View results in: %cd%
ECHO =================================================
PAUSE

@ECHO OFF
SETLOCAL enableextensions
TITLE Local Build Enumeration Tool
:: This script attempt to retrieve some useful information from the system and domain
ECHO =================================================
ECHO          Local Windows Build Reviewer
ECHO =================================================
ECHO.
echo Starting enumeration for:
hostname
ECHO.
MKDIR LWBR-Results
ECHO [+] Created folder "LWBR-Results"
CD LWBR-Results
ECHO [+] Started [ %date% - %time% ]
ECHO.

ECHO Running Local Checks..
:: Local Checks
systeminfo >> SystemInfo.txt
wmic qfe list >> Windows-Patches.txt
net share >> Shares.txt
net localgroup >> Local-Groups.txt
net users >> Local-Users.txt
net accounts >> Local-PW-Policies.txt
GPResult /R >> GP-Result.txt
findstr /si password *.xml *.ini *.txt >> Local-Passwords.txt
findstr /spin "password" *.* >> Local-Passwords.txt
schtasks /query /fo LIST /v >> Scheduled-Tasks.txt
:: otherwise use: tasklist /SVC
powershell Get-ExecutionPolicy >> Powershell-Policy.txt
ECHO.

ECHO Checking for insecure services..
:: Insecure services / unquoted paths
wmic /OUTPUT:"Insecure-Services.txt" service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
ECHO.
ECHO Checking Registry..
:: Registry entries with "reg"
:: check for passwords in the registry
reg query HKLM /f password /t REG_SZ /s >> REG-Passwords.txt
reg query HKCU /f password /t REG_SZ /s >> REG-Passwords.txt
ECHO.

ECHO Checking Installed Software..
:: Installed programs
wmic /output:"Software.txt" product get Name, Version, Vendor
ECHO.

ECHO Checking Network Settings..
:: Network Checks
ipconfig /all >> IPConfig.txt
PING www.google.com >> InternetAccess.txt
route PRINT >> Route.txt
netstat -ano >> Netstat.txt
tracert google.com >> Traceroute.txt
arp -A >> ARP-Table.txt
ECHO.

ECHO Getting Domain Information..
:: Domain Checks
net view /domain >> Domain-Info.txt
net accounts /domain >> Domain-PW-Policy.txt
net users /domain >> Domain-Users.txt
net groups /domain >> Domain-Groups.txt
nltest /dclist >> Domain-Controller.txt
ECHO.

ECHO Retrieving Firewall Configuration..
:: Firewall Checks
netsh firewall show state >> Firewall-State.txt
netsh firewall show config >> Firewall-Config.txt
ECHO.

ECHO [+] Finished! [ %date% - %time% ]
ECHO.
ECHO View results in: %cd%
PAUSE
@echo off
>shopping_changes.txt (
echo SHOPPING LIST V1
echo ^@panscanned, github.com/joeavanzato/EyeOfTheBeholder/
echo -------------------------------
echo ------ SYSTEM INFORMATION ------
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
echo ------ HOSTNAME ------
hostname
echo ------ USERNAME / PRIVILEGES------
echo CHECK FOR SeAssignPrimaryTokenPrivilege SeImpersonatePrivilege
echo %username%
whoami /all
echo ------ LOCAL USERS ------
net users
echo ------ LOCAL GROUPS   ------
net localgroup
echo -----------------------------------------------------
echo ------ HOTFIX INFORMATION ------
wmic qfe get Caption,Description,HotFixID,InstalledOn
echo -----------------------------------------------------
echo ------ NETWORK INTERFACE CONFIGURATIONS ------
ipconfig /all
echo -----------------------------------------------------
echo ------ TRACE ROUTE   ------
route print
echo -----------------------------------------------------
echo ------ ARP TABLE ------
arp -A
echo -----------------------------------------------------
echo ------ FIREWALL STATE / CONFIGURATION ------
netsh firewall show state
netsh firewall show config
echo -----------------------------------------------------
echo ------ ACTIVE NETWORK CONNECTIONS ------
netstat -ano
echo -----------------------------------------------------
echo ------ SCHEDULED TASK LIST ------
schtasks /query /fo LIST /v 
echo -----------------------------------------------------
echo ------ RUNNING TASKS ------
tasklist /SVC
echo -----------------------------------------------------
echo ------ RUNNING SERVICES ------
net start
echo -----------------------------------------------------
echo ------ Checking AlwaysInstallElevated Keys ------
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
echo -------------------------------------------------
echo ------ WRITEABLE DIRECTORY SEARCH ------
dir /a-r-d /s /b
echo -----------------------------------------------------
echo ------ CHECK FOR UNQUOTED SERVICE EXECUTABLE PATHS ------
sc query state=all | findstr "SERVICE_NAME:" >> a & FOR /F "tokens=2 delims= " %%i in (a) DO @echo %%i >> b & FOR /F %%i in (b) DO @(@echo%%i & @echo --------- & @sc qc %%i | findstr "BINARY_PATH_NAME" & @echo.) & del a 2>nul b 2>nul
echo -----------------------------------------------------
echo ------ CHECK ACTIVE DOMAIN CONTROLLER ------
set 1
echo -----------------------------------------------------
echo ------ LIST KERBEROS TICKETS ------
klist
echo -----------------------------------------------------
echo ------ LIST LOGON SESSIONS VIA KERBEROS ------
klist tgt
echo -----------------------------------------------------
echo ------ CHECK FOR STORED CREDENTIALS IN REGISTRY ------
cmdkey /list
echo -----------------------------------------------------
echo ------ CHECK POWERSHELL EXECUTION POLICY ------
powershell Get-ExecutionPolicy
echo -----------------------------------------------------
echo ------ SENSITIVE FILES CONTAINING CREDENTIALS ------
IF EXIST c:\sysprep.inf  ECHO c:\sysprep.inf found!
IF EXIST c:\sysprep\sysprep.xml  ECHO c:\sysprep\sysprep.xml found!
IF EXIST %WINDIR%\Panther\Unattend\Unattended.xml  ECHO %WINDIR%\Panther\Unattend\Unattended.xml found!
IF EXIST %WINDIR%\Panther\Unattended.xml  ECHO %WINDIR%\Panther\Unattended.xml found!
echo -----------------------------------------------------
echo ------ INTERESTING FILES ------
dir /s *pass* == *cred* == *vnc* == *.config*
Rem echo ----- VERY NOISY ------
Rem #VERY NOISY - findstr /si password \*.xml \*.ini \*.txt
echo -----------------------------------------------------
echo ------ PROXY CONFIGURATION AND CONNECTIVITY CHECKS ------
netsh winhttp show proxy
echo ------ ICMP PING CHECK ------
ping 8.8.8.8
echo ------ DNS RESOLUTION CHECK ------
nslookup cnn.com
nslookup reddit.com
nslookup youtube.com
nslookup github.com
echo ------ FIREWALL RULE DUMP ------
netsh advfirewall firewall show rule name=all

)

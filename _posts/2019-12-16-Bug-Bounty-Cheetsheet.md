---
title: Bug Bounty Cheatsheet
tags: [Windows Cheatsheet,Active Directory,Exploitation,Priv Esc,Post Exploit,File Transfer,Lateral Movement]
published: true
description: A place for me to store my notes/tricks for Bug Bounty Hunting - Big Work in Progress :). 
toc: true
image: https://i.pinimg.com/originals/7a/b0/b8/7ab0b884b7050bbae9cc976409cd5567.png
thumbnail: https://i.pinimg.com/originals/7a/b0/b8/7ab0b884b7050bbae9cc976409cd5567.png
---




# [](#header-1)Bug Bounty Cheatsheet

This is a massive WIP and may seem a bit blank at the moment but I have a lot to add here I just need to remember to do it and migrate my own-custom scripts onto here as a individual commands. 

## [](#header-2) Enumeration / Recon

### [](#header-3) Sub Domain Enumeration

**Basic Enumeration with Subfinder**

```powershell
Make sure all API keys are populated, Shodan pro account is beneficial :) 

Subfinder -d domain.com -o Outfile.txt
```



**Rapid7 FDNS**

```powershell
https://opendata.rapid7.com/sonar.fdns_v2/

aptitude install jq pigz
wget https://scans.io/data/rapid7/sonar.fdns_v2/20170417-fdns.json.gz
cat 20170417-fdns.json.gz | pigz -dc | grep ".target.org" | jq`
```



**Generate Basic Permutations**

```bash
I have a small bash loop to handle this 

#!/bin/bash
for i in $(cat /home/aidan/Tools/alterations.txt); do echo $i.$1; 
done;
```



**AMass Basic Active Scan**

```powershell
You could do with a amass passive scan and not resolve domains with MassDNS later but I usually just go with active :) 

amass enum -d domain.com
```



**Certificate Transparency Logs**

```powershell
python3 $BugBounty crt.sh domain.com

This script be found in my GitHub repo, it just takes a domain and passes it to crt.sh and aggerates the output. 
```



**Subdomain Brute Force (Subbrute & MassDNS)**

```bash
$Tools/subbrute.py $Tools/massdns/lists/names.txt domain.com | massdns -r $Tools/massdns/lists/resolvers.txt -t A -a -o -w massdns_output.txt -
```



**Generate Permutations with AltDNS**

```bash
altdns -i input_domains.txt -o ./output/path -w $Tools/altdns/words.txt
```





**Fuzzing Subdomains with WFuzz**

```bash
wfuzz -c -f re -w /SecLists/Discovery/DNS/subdomains-top1mil-5000.txt -u "http://domain.htb" -H "Host: FUZZ.domain.htb" --hh 311\
```











### [](#header-3) Google Dorks

```powershell
https://drive.google.com/file/d/1g-vWLd998xJwLNci7XuZ6L1hRXFpIAaF/view

site:your-target.com inurl:id=
site:your-target.com filetype:php
site:your-target.com intitle:upload
inurl:”.php?id=” intext:”View cart”
inurl:”.php?cid=” intext:”shopping”
inurl:/news.php?include=
inurl:”.php?query=”


#Open Redirect
inurl:url=https
inurl:url=http
inurl:u=https
inurl:u=http
inurl:redirect?https
inurl:redirect?http
inurl:redirect=https
inurl:redirect=http
inurl:link=http
inurl:link=https
```


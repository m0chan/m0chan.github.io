---
title: Bug Bounty Cheatsheet
tags: [Bug Bounty,Web App,Subdomain Enumeration,Cheatsheet]
published: true
description: A place for me to store my notes/tricks for Bug Bounty Hunting - Big Work in Progress :). 
toc: true
image: https://i.pinimg.com/originals/7a/b0/b8/7ab0b884b7050bbae9cc976409cd5567.png
thumbnail: https://i.pinimg.com/originals/7a/b0/b8/7ab0b884b7050bbae9cc976409cd5567.png
---



This is a massive WIP and may seem a bit blank at the moment but I have a lot to add here I just need to remember to do it and migrate my own-custom scripts onto here as a individual commands. 



Also before I continue these are my main references that have helped me build my own methodology.

* https://0xpatrik.com/subdomain-enumeration-2019/ - **Main One**
* https://pentester.land/conference-notes/2018/08/02/levelup-2018-the-bug-hunters-methodology-v3.html - **Main One**
* https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html
* https://blog.usejournal.com/bug-hunting-methodology-part-1-91295b2d2066

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



**Scan.io**

```powershell
Numerous repos & large dumps from various sources of Scans.

https://scans.io/
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



**Find Resolvable Domains with MassDNS**

```bash
massdns -r $Tools/massdns/lists/resolvers.txt -t A -o S allsubdomains.txt -w livesubdomains.messy

sed 's/A.*//' livesubdomains.messy | sed 's/CN.*//' | sed 's/\..$//' > domains.resolved
```



**Find HTTP/HTTPS Servers with HTTProbe**

```powershell
cat domains.resolved | httprobe -c 50 | tee http.servers
```



**Pass HTTProbe Results to EyeWitness**

```powershell
cp http.servers $Tools
$Tools/EyeWitness/eyewitness.py --web -f http.servers
```



**Pass All Subdomains too S3 Scanner**

```powershell
Even if a subdomain does not follow normal bucket naming conventtion it may be resolving to an unsecured one. 

Therefore run the following

python $Tools/S3Scanner/s3scanner.py -l domains.resolved -o buckets.txt

-d flag will dump all open buckets locally

If you find open buckets you can run the useful bash look to enumerate content

for i in $(cat buckets.txt); do aws s3 ls s3://$i; done;

This will require basic auth key/secret which you can get for free from AWS
```





**Fuzzing Subdomains with WFuzz**

```bash
wfuzz -c -f re -w /SecLists/Discovery/DNS/subdomains-top1mil-5000.txt -u "http://domain.htb" -H "Host: FUZZ.domain.htb" --hh 311\
```



### [](#header-3) ASN Enumeration

I wasn't sure if I should add this under **Subdomain Enumeration** but doesn't really matter. Here are a few techniques to discover subdomains and ports via companies publicly available ASN numbers. 



**Find Organistations ASN's**

```bash
amass intel -org paypal
1449, PAYPAL-CORP - PayPal
17012, PAYPAL - PayPal
26444, PAYDIANT - PayPal
59065, PAYPALCN PayPal Network Information Services (Shanghai) Co.
206753, PAYPAL-
```



**Find IPv4 Address Space from ASN**

```powershell
I have yet to find a good tool to do this so I will be writing something in Go very shortly, but in the meantime you can simple visit 

https://bgp.he.net/ASNNumberHere#_prefixes

https://bgp.he.net/AS17012#_prefixes

Correction: You can start scanning ASNs directly with the below command

amass -d paypal.com -asn 17012
```

<img src="http://i.imgur.com/ydjR8W9.png"></img>



**Parse CIDR from ASN Lookup too AMass Enum**

```bash
amass enum -d paypal.com -cidr 64.4.240.0/21

I have found to have really good results using `amass enum` here + large CIDR range however sometimes these can be false positives/dead hosts so remember to verifiy with MassDNS if they are live.
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


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
* https://payhip.com/b/wAoh - **Main One (Awesome Book)**
* https://pentester.land/conference-notes/2018/08/02/levelup-2018-the-bug-hunters-methodology-v3.html - **Main One**
* https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html
* https://blog.usejournal.com/bug-hunting-methodology-part-1-91295b2d2066

## [](#header-2) Enumeration / Recon



### [](#header-2) Initial Stuff



Before we jump into Subdomain Enumeration which is typically the first step for any program that has a wildcard scope `*.domain` It's worth mentioning a few things and different locations we can get data from. 



Also a small tip moving forward, if you are going to get into Bug Bounty I recommend that you rent yourself a VPS as it will help a lot when carrying out long & CPU intensive tasks. It will also help you offload heavy tasks and allow you to keep your main workstation for manual testing and recon etc. 



My personal preference is Linode.com as I have used them for 4/5 years without a single issue and it is not a pay-as-you-go service like DigitalOcean.



Referral Code: https://www.linode.com/?r=91c07fff7abd148b08880020c558d5cace801cc3



**Port Scanning IP Ranges**

```powershell
First tip is to use Basic Shodan, Google Dorks & ASN lookups to find target CIDR ranges - If you are attacking a very large program this be thousands of IP addresses but is usually worth it and definetely a background task to consider. 

You can then import all the scans into something like this for a nice overview

https://ivre.rocks/

Small Tips:

1) Run this on a VPS (Linode.com is my go-to)
2) Run inside a screen session with Screen -SmL
3) Pipe the output with | tee 

Btw, some people will tell you to use massscan due to the speed but I find it misses a lot of ports so VPS+ nMap + Screen is the most reliable.  
```





*More to follow here....* 




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



**Assetfinder by Tomnomnom**

```powershell
https://github.com/tomnomnom/assetfinder

Of course Tomnomnom was going to appear here (alot) he has a lot of resources for BugBounty and assetfinder is an awesome place to start for easy wins

go get -u github.com/tomnomnom/assetfinder

assetfinder domain.com

You need to set a couple API/Tokens for this too work, similar too Subfinder

facebook
Needs FB_APP_ID and FB_APP_SECRET environment variables set (https://developers.facebook.com/)

virustotal
Needs VT_API_KEY environment variable set (https://developers.virustotal.com/reference)

findsubdomains
Needs SPYSE_API_TOKEN environment variable set (the free version always gives the first response page, and you also get "25 unlimited requests") — (https://spyse.com/apidocs)

```



**WaybackURLs - Fetch all URL's that WayBackMachine Knows About a Domain**

```powershell
#https://github.com/tomnomnom/waybackurls


cat subdomains | waybackurls > urls
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



**Finding CNames for all Domains**

```bash
massdns -r massdns/lists/resolvers.txt -t CNAME -o S -w paypal.massdns.cnames paypal.subdomains

cat paypal.subdomains | grep trafficmanager
cat paypal.subdomains | grep azure
```



**Subdomain Bruteforcing with all.txt**

```powershell
https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056

todo - As there is a few methods to talk about here but the best wordlists is Jason Haddix's all.txt
```



**Subdomain Bruteforcing with Commonspeak Wordlists**

```powershell
#https://github.com/assetnote/commonspeak2
#https://github.com/assetnote/commonspeak2-wordlists

Common speak from Assetnote has a unique way of generating wordlists and
one of my favorite wordlists to use for subdomain brute forcing. There are
numerous datasets on Google Big query that are constantly being updated with
new information. These datasets are used by common speak to create a wordlist
that contain current technologies and terminology.

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
```

<img src="http://i.imgur.com/ydjR8W9.png"></img>



**Parse CIDR from ASN Lookup too AMass Enum**

```bash
amass enum -d paypal.com -cidr 64.4.240.0/21

I have found to have really good results using `amass enum` here + large CIDR range however sometimes these can be false positives/dead hosts so remember to verifiy with MassDNS if they are live.
```





### [](#header-3) Basic Content Finding

Here I will discuss some basic tactics once you have a nice list of live subdomains



**Find Easy Wins with DirSearch**

```powershell
Of course if we have a large amount ot subs we can't just send over directory-list-2.3medium so I typically use this small list against all the subdomains and (or) ip ranges from ASN lookups. 

/phpinfo.php
/info.php
/admin.php
/api/apidocs
/apidocs
/api
/api/v2
/api/v1
/v2
/package.json
/security.txt
/application.wadl
/api/apidocs
/swagger
/swagger-ui
/swagger-ui.html
/swagger/swagger-ui.html
/api/swagger-ui.html
/v1.x/swagger-ui.html
/swagger/index.html
/graphql
/graphiql

python3 dirsearch.py -L http.servers -e .* -w paths --simple-report=dirsearch.paypal -t 50 

Be careful with the -t flag, I am using a pretty beefy VPS for this stage :) 
```



**dirSearching with RobotsDisallowed1000.txt**

```powershell
This is similar to the previous method but we are using a Wordlist supplied with SecLists that details the top 1000 entries inside Robots.txt

https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/RobotsDisallowed-Top1000.txt

This usually dosent take too long but can be depending on the scope.

Tip: Run this on a VPS

I have had some nice success with raft-large-files.php 

python3 dirsearch.py -L http.servers -e .* -w RobotsDisallowed-Top1000.txt --simple-report=dirsearch.paypal -t 50 

Be careful with the -t flag, I am using a pretty beefy VPS for this stage :) 
```



**Excessive DirSearching with RAFT**

```powershell
This may take a very long time to run and timeout depending on your scope but these lists are the goto when it comes to dirbusting

Tip: Run this on a VPS

https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-large-directories.txt

https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-large-files.txt

I have had some nice success with raft-large-files.php 

python3 dirsearch.py -L http.servers -e .* -w wordlist --simple-report=dirsearch.paypal -t 50 

Be careful with the -t flag, I am using a pretty beefy VPS for this stage :) 
```




**Meg - Find Many Paths for Hosts (Similar to DirSearch)**

```powershell
#https://github.com/tomnomnom/meg

meg --verbose paths http.servers

This will create a /out folder with results from each web server (use this after httprobe) - Then we can simply start grepping for juicy stuff

grep -r api
grep -r phpinfo

etc etc
```



**WaybackURLs - Fetch all URL's that WayBackMachine Knows About a Domain**

```powershell
#https://github.com/tomnomnom/waybackurls


cat subdomains | waybackurls > urls
```



**Tomnomnom's Concurl**

```powershell
#https://github.com/tomnomnom/concurl


▶ cat urls.txt
https://example.com/path?one=1&two=2
https://example.com/pathtwo?two=2&one=1
https://example.net/a/path?two=2&one=1

▶ cat urls.txt | concurl -c 3
out/example.com/6ad33f150c6a17b4d51bb3a5425036160e18643c https://example.com/path?one=1&two=2
out/example.net/33ce069e645b0cb190ef0205af9200ae53b57e53 https://example.net/a/path?two=2&one=1
out/example.com/5657622dd56a6c64da72459132d576a8f89576e2 https://example.com/pathtwo?two=2&one=1

▶ head -n 7 out/example.net/33ce069e645b0cb190ef0205af9200ae53b57e53
cmd: curl --silent https://example.net/a/path?two=2&one=1



Concurrent HTTP Requests because Go is fast as f
```


**Get All Subdomain HTTP Headers & Responses**

```bash
#Reference: https://medium.com/bugbountywriteup/fasten-your-recon-process-using-shell-scripting-359800905d2a

Cool little bash loop to handle this, we will loop through all the found http/https servers from httprobe and grab the headers and responses. 

Great way to find legacy web servers or quickly check the reponses to find easy wins. 

Stored as GetAllHeadersandResponses.sh in my repo :)

Todo: I will rewrite this to support Tomnomnoms concurl to carry out concurrent http requests when I have time :) 


#!/bin/bash
mkdir headers
mkdir responsebody
CURRENT_PATH=$(pwd)
for x in $(cat $1)
do
        NAME=$(echo $x | awk -F/ '{print $3}')
        curl -X GET -H "X-Forwarded-For: evil.com" $x -I > "$CURRENT_PATH/headers/$NAME"
        curl -s -X GET -H "X-Forwarded-For: evil.com" -L $x > "$CURRENT_PATH/responsebody/$NAME"
done


In the next step I will show how we can use the collected data to grab all Javascript files from the endpoints :) There is also another way with JSearch which I will show further down. 
```



**Collecting JavaScript Files**

```bash
#Reference: https://medium.com/bugbountywriteup/fasten-your-recon-process-using-shell-scripting-359800905d2a

This script will crawl all the responses from the previous script and store all javascripts files inside domain.com/scripts

This is a good tactic as sometimes devs will hardcore API keys/tokens etc in Javascript files without realising. 

Stored as GetJSFiles.sh in my repo :)

#!/bin/bash
mkdir scripts
mkdir scriptsresponse
RED='\033[0;31m'
NC='\033[0m'
CUR_PATH=$(pwd)
for x in $(ls "$CUR_PATH/responsebody")
do
        printf "\n\n${RED}$x${NC}\n\n"
        END_POINTS=$(cat "$CUR_PATH/responsebody/$x" | grep -Eoi "src=\"[^>]+></script>" | cut -d '"' -f 2)
        for end_point in $END_POINTS
        do
                len=$(echo $end_point | grep "http" | wc -c)
                mkdir "scriptsresponse/$x/"
                URL=$end_point
                if [ $len == 0 ]
                then
                        URL="https://$x$end_point"
                fi
                file=$(basename $end_point)
                curl -X GET $URL -L > "scriptsresponse/$x/$file"
                echo $URL >> "scripts/$x"
        done
done


This method can be a little slow as there is no multithreading involved, but works perfect for smaller programs :)
```





**Finding Hidden Endpoints from Scraped JS Files**

```bash
#Reference: https://medium.com/bugbountywriteup/fasten-your-recon-process-using-shell-scripting-359800905d2a

#Dependancy: https://github.com/jobertabma/relative-url-extractor

Similar to the previous scripts this bash script will require the previous scripts to be run as it relys on the output. 

What we do here is parse the relative paths present in the scraped JS Files, this way we can find some interesting endpoints and configurations which may have some vulnerable parameters. 

Providing we have 'relative-url-extractor' installed we can use the following bash script to achieve what we need.

Stored in my Repo as HiddenEndpointLoop.sh

#!/bin/bash
#looping through the scriptsresponse directory
mkdir endpoints
CUR_DIR=$(pwd)
for domain in $(ls scriptsresponse)
do
        #looping through files in each domain
        mkdir endpoints/$domain
        for file in $(ls scriptsresponse/$domain)
        do
                ruby ~/relative-url-extractor/extract.rb scriptsresponse/$domain/$file >> endpoints/$domain/$file 
        done
done


```





**Port Scanning Subdomains**

```powershell
I won't get into this much as it's fairly straight forward, simply parse your subdomains.resolved too nmap with your preferred syntax and let it run away.

Small Tips:

1) Run this on a VPS (Linode.com is my go-to)
2) Run inside a screen session with Screen -SmL
3) Pipe the output with | tee 

Btw, some people will tell you to use massscan due to the speed but I find it misses a lot of ports so VPS+ nMap + Screen is the most reliable.  
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
inurl:redirectUrl=http site:paypal.com
```


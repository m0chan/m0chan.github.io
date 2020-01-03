---
title: How I Took Over 2 Subdomains with Azure CDN Profiles
tags: [Bug Bounty, Subdomain Takeover, Subjack, Subfinder]
description: I recently was carrying out some Bug Bounty hunting on a new program and came across 2 subdomains which resolved to a unclaimed Azure CDN Profile which I was able to claim.  
published: true
image: https://cdn1.iconfinder.com/data/icons/seo-solid-black/32/seo-solid-set-03-512.png
thumbnail: https://cdn1.iconfinder.com/data/icons/seo-solid-black/32/seo-solid-set-03-512.png
---



##  Introduction



Recently I have ramped up my Bug Bounty hunting and overall hours spent attacking programs and hunting vulns with quite a bit of success. I decided to start enumerating a program which offered a wildcard scope but sadly I cannot disclose hence the redactions :)



While I was carrying out my usual Recon and Subdomain Enumeration I came across numerous subdomains that had **CNAMES** resolving to vacant Azure CDN Profiles domains which I was able to register and point towards my own web server, theoretically taking over the subdomain and obtaining the ability to serve content utilizing one of the `in-scope` domains.  



##  Basic Enumeration



For basic enumeration I just followed my usually enumeration process which can be found in detail [Here](https://m0chan.github.io/2019/12/16/Bug-Bounty-Cheetsheet.html)

After a couple hours I finally had a list of around 600 subdomains which I was able to enumerate in greater detail with tools such as `massdns` and `subjack` - Very shortly I discovered multiple domains that had `CNAMES` resolving to azure domains that responded with `NXDOMAIN`



## Exploiting / PoC



The final list of potentially vulnerable services contained domains similar to the below.

	*.trafficmanager.net
	*.azurewebsites.net
	*.azureapp.com
	*.azureedge.net



After an hour or two of going through each domain and trying to register it in various resources such as TrafficManager profiles, CloudApps etc I came to a dead end and started to look at `azureedge.net` domains which I hadn't seen until now. At first I did not think it was possible to register these domains or gain access easily I finally came across `CDN Profiles` in the azure portal after registering for a free account. 



Initially I had absolutely no idea how to register a `CDN Profile` & was also very scared of getting billed a crazy amount but I just went with it and registered both vacant `CNAMES` with the help of the article below. 

https://andyrush.io/2019/09/28/subdomain-takeover-for-azure-cdn/



I do not want to plagurize Andy's article as he did a great job of explaining but the general PoC layout was as follows

 * Enumerate Domain with **CNAME** Pointing to `xxxx.azureedge.net`
 * Create Free / Pay-As-You-Go Account on portal.azure.com
 * Create New `CDN Profile`
 * Configure CDN Endpoint with Previously Enumerated `azureedge.net` Domain
   	* If it shows as green when you enter it means it's vulnerable to takeover :) 
* Configure New CDN Profile to Route to Location of your choice, in my case I pointed it to my own web server with a simple PoC Page. 
*  Access original domain with `in-scope domain` - Domain should resolve to the `CNAME` before finally routing to your web server :) 



  <img src = "http://i.imgur.com/YLUhICn.png">





Also a small note once I configured the `CDN Profile`, I spent over an hour troubleshooting why the domain was resolving to the 'right place' but not showing my content aka webserver page, in the end it came down to 2 reasons

 * No Custom Domain Set
   	* This is set within the `CDN Profile` and should specify the original domain which you have taken over aka the vulnerable domain
 * CDN Required Purged
   	* This was probably pretty obvious but caught me out, it seems that the CDN is caching pretty excessively and requires purged everytime you make a change to the web server content etc, in my case it was when I uploaded a simple HTML PoC. I would imagine there is some timer within Azure that controls purging automatically but it's easier to just do it manually with the `Purge` option within `CDN Profiles` 



 ## Timeline



**Sat 14th Dec 2019** - Reported to Platform

**Tues 17th Dec 2019** - Accepted/Triaged

**Thur 19th Dec 2019** - Bounty Awarded $$$ 


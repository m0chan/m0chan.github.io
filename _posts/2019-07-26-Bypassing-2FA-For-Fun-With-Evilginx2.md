---
title: Bypassing 2FA For Fun With Evilginx2
tags: [2FA Bypass,Phishing,Evilginx2]
description: I recently decided to explore phishing techniques and 2FA Bypasses to further understand how attackers are compromising accounts/networks with 2FA enabled and to further demonstrate why organisation should not solely rely on 2FA to protect there sensitive assets. 
thumbnail: https://1.bp.blogspot.com/-mQLYyPCi_hs/W7CjcrOXK-I/AAAAAAAANgI/A_cCDjTE1RIDNywRJZd30x77_cWWQoiuwCLcBGAs/s1600/Evilginx%2B2%2Blogo%2Bmin.png
published: true
---



## [](#header-2)Introduction

I recently decided to explore phishing techniques and 2FA Bypasses to further understand how attackers are compromising accounts/networks with 2FA enabled and to further demonstrate why organisation should not solely rely on 2FA to protect there sensitive assets. 

Of course there are conventional phishing techniques where an attacker can clone a login interface, host it on there own web server and siphon the credentials but 2FA mitigate's this... Then I discovered Evilginx2 - Evilginx2 is a little bit different in the sense that it acts as a MITM-Proxy connecting to 2FA protected sites and handling the authentication itself and merely just acting as a passthrough from the victim -> server. The below images provides a good picture.

![](https://breakdev.org/content/images/2018/07/evilginx2_diagram.png)

TL;DR: [https://github.com/kgretzky/evilginx2](Evilginx2 Github).



## [](#header-2)Infrastructure Setup

Once I found out about Evilginx2 I had to try it for myself so as the Github said I opt'd for a VPS with Digital Ocean. You can use my referral link here & get $50 free credit (Enough for 1 Month VPS) 

[Digital Ocean Referral](https://m.do.co/c/aa9fa82f580a).



I also picked myself up a domain for testing purposes (https://offffice.co.uk) - Yes I managed to get `Office` with 4 F's for £1... 



Now I was armed with a Ubuntu box & a domain I was ready to start configuring Evilnginx2 & start phishing :) 



First I SSH'd into my box with 

```
ssh -i id_rsa root@m0chandroplet
```

And ran the below commands

```
sudo apt-get install git make
go get -u github.com/kgretzky/evilginx2
cd $GOPATH/src/github.com/kgretzky/evilginx2
make
sudo make install
nano /etc/resolv.conf
nameserver 8.8.8.8
service systemd-resolved stop
evilginx
```



I also did not include the installation of `GO` as there are numerous tutorials out there. Also worth noting I installed `Evilginx2` under the `root` user but I would strongly advise installing with a lower priv user in production for obvious reasons.



Now my Ubuntu box was configured and ready to go I had to configure my domain `offffice.co.uk` with relevant `A` records & `nameserver`

Therefore I created the below records

`ns1.offffice.co.uk -> Droplet IP`

`ns2.offffice.co.uk -> Droplet IP`

`A account.offffice.co.uk -> Droplet IP`

`A outlook.offffice.co.uk -> Droplet IP`

`A login.offffice.co.uk -> Droplet IP`

Worthwhile noting that I only configured it for Microsoft Platforms `outlook` & `o365` but of course if you were attacking Facebook, Linkedin you would create a relevant `A` record i/e `facebook.offffice.co.uk` 

Okay - Now we're set let's configure `Evilnginx2` itself.



## [](#header-2)Evilginx2 Setup

Let's jump straight into it and jump into it by running `evilginx2` - Little tip I advise installing `screens` so you can easily background `evilginx2` and so it won't close when you exit your SSH session. I'm sure if you are reading this you have heard of `screen` though :)



![](https://i.imgur.com/WtRxfT5.png)



Now we have to run the below commands to configure our Server IP & Domain Name

```
config domain offffice.co.uk
config ip Droplet-IP
phishlets hostname o365 offffice.co.uk
phishlets hostname outlook offffice.co.uk
phishlets enable o365
phishlets enable outlook
```



What makes `evilginx2` so great is that once you run the above commands it will automatically go out and grab an SSL Cert for all relevant domains from `LetsEncrypt` so your victims do not get any `SSL` warnings



Now finally we have one more step to do and that is configure a `lure` - Lures are basically the extention after the phishing domain i/e `https://outlook.offffice.co.uk/hjk7234` (This is the domain you would send to your victims)

 

## [](#header-2)Execution

Now our infrastructure is perfectly configured, DNS is configured & phishlets are configured we can now send our domains to our victims. 

For my testing I primarily used `outlook` & `o365` but for this article I will stick with `outlook` as it easier to get a `2FA` enabled account. In my case my phishing link was `https://outlook.offffice.co.uk/LnhgUquX`



I will leave the delivery of this link upto your own imagination, we have all seen spam emails and how easily it is to design something that looks identical to a normal `Microsoft` email alert. It's only basic html. 



Now upon visiting my link I was granted with the below page



![](https://i.imgur.com/LOv53fN.jpg)



Unless you had a very keen eye you would struggle to notice anything was amiss. So now if I log in with my test account `m0chanxxxxxxxx@outlook.com` and enter my password I will get a `2FA` prompt which will send a text message to my phone. 

I enter the code as normal and get successfully logged in to Outlook like nothing ever happened. 

![](https://i.imgur.com/96vtqu7.png)



As you can see we are perfectly logged in and can see our Inbox



Now lets jump back over to my `evilginx` instance and see what I have retrieved. 

![](https://i.imgur.com/CnSb5QS.png)

**Boom** - We have the Username & Password in clear text as well as all authorization tokens. This is bad. Really bad. 

If we have the auth/session tokens we can now import these into any browser with a Cookie Manager and get logged straight in without even entering the username & password. We just simply hijack the users session.





![](https://i.imgur.com/UVFehzh.png)



As you can see in the above screenshot we have got the full details including username/password and the auth token which can import into our browser with Cookie Manager for Chrome. See below screenshot.

![](https://i.imgur.com/8LoGTjg.png)



Once we click the green tick, boom we are straight into the account. No further action required. No new 2fa tokens pushed to our devices. Nothing. **We are in**.



## [](#header-2)Defending Yourself From Evilginx2

The major flaw in this attack is the fact that you have to use a domain controlled by yourself but I have demonstrated how easy it is to get a lookalike domain such as `offffice.co.uk` 

That being said users should always check the domain in full and compare it to known sources especially when logging into sensitive platforms.

Also this attack will not work where platforms have `U2F` aka `Universal 2nd Factor Authentication` enabled. 

`U2F` are hardware keys such as Yubi keys, `U2F` has a very clever security mechanism inbuilt where it will not issue a `2FA` token if the domain does not match the legit domain. In this case `offffice.co.uk` does not match `office.co.uk`



## [](#header-2)Conclusion



I hope you have enjoyed reading this write-up and have a better picture of why organizations should not solely rely on `2FA` to protect there sensitive resources. 

Also. Hardware Keys ftw.... 


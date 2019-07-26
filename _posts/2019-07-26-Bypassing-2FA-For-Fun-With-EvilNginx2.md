---
title: Bypassing 2FA For Fun with Evilginx2
published: true
---

## [](#header-2)Introduction

I recently decided to explore phishing techniques and 2FA Bypasses to further understand how attackers are compromising accounts/networks with 2FA enabled and to further demonstrate why organisation should not solely rely on 2FA to protect there sensitive assets. 

Of course there are conventional phishing techniques where an attacker can clone a login interface, host it on there own web server and siphon the credentials but 2FA mitigate's this... Then I discovered Evilginx2 - Evilginx2 is a little bit different in the sense that it acts as a MITM-Proxy connecting to 2FA protected sites and handling the authenticating itself and merely just acting as a passthrough from the victim -> server. The below images provides a good picture.

Evilginx2 has the ability to bypass 2FA on Outlook, Linkedin, O365, Twitter, Instagram, Github, Amazing, Reddit, Facebook & more...

![](https://breakdev.org/content/images/2018/07/evilginx2_diagram.png)



Evilginx2 - _A Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication_

TL;DR: [https://github.com/kgretzky/evilginx2](Evilginx2 Github).

There should be whitespace between paragraphs.



## [](#header-2)Infrastructure Setup

> This is a blockquote following a header.
>
> When something is important enough, you do it even if the odds are not in your favor.

Once I found out about Evilginx2 I had to try it for myself so as the Github said I opt'd for a VPS with Digital Ocean. You can use my referral link here & get $50 free credit (Enough for 1 Month VPS )[https://m.do.co/c/aa9fa82f580a](Digital Ocean Referral).



I also picked myself up a domain for testing purposes (https://offffice.co.uk) - Yes I managed to get 'Office' with 4 F's for £1... 



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

Let's jump straight into it and jump into it by running `evilginx2` - Little tip I advise installing `screens` so you can easily background `evilginx2` and so it won't close when you exit your SSH session. I'm sure if you are reading this you have heard of `screens`though :)



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



Unless you had a very keen eye you would struggle to notice anything was amiss.

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

![](https://breakdev.org/content/images/2018/07/evilginx2_diagram.png)


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

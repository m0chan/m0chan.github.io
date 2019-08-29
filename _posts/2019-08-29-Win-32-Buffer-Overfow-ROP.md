---
title: Win32 Buffer Overflow - ROP & DEP Bypass
tags: [Buffer Overflow,Exploit Development,Windows,ROP,DEP,OSCE]
description: SEH is a mechanism within Windows that makes use of a data structure/layout called a Linked List which contains a sequence of memory locations. When a exception is triggered the OS will retrieve the head of the SEH-Chain and traverse the list and the handler will evaluate the most relevant course of action to either close the program down graceful or perform a specified action to recover from the exception.
thumbnail: https://png.pngtree.com/element_our/sm/20180224/sm_5a90fde8c56d5.png
published: false
---





# Introduction





Welcome to Part 3 of my Win32 Buffer Overflow series where I am writing an article for each stage of my learning Win32 Exploit Development, so far I have covered [Simple EIP Overwrite's](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) & [SEH Overflow's w/ Egghunters](https://m0chan.github.io/2019/08/21/Win32-Buffer-Overflow-SEH.html) - If you have not read those I recommended you go back and give them a read! There is a lot of information and I spent a lot of time writing them. 



If you have been following, great! But you will have noticed up until this point I have only been focusing on the *exploit* part and not really considering **DEP** or **ASLR** as we turned them off on our Test-VM in Part 1. Well for this part I am going to enable **DEP** on my Test VM and discuss the ways we can bypass this with `ROP Chains` and of course show some examples. 



*If you are following along I advise you re-enable **DEP** by using **EMET GUI***



**Table of Contents**



Let's jump right into it. 







## What is DEP (Data Execution Protection) ? 



So far in this series we have been exploiting vulnerabilties to control the execution flow of our program with the aim to redirect to our shell code typically placed on the stack - Well if we had **DEP** enabled throughout these exercises we would not be able to do this. 



It's worth mentioning that there are 2 different types of **DEP** - **Hardware DEP** & **Software DEP**.  Throughout this article I will be sticking to **Hardware DEP / NX**.



- **Hardware Enforced DEP** - *CPU Marks pages of Memory as NX*
- **Software Enforced DEP** - *Alternative for CPU's without NX ability and implemented by developer*



**DEP** mitigates executing shell code placed on the stack by enforcing **non-executable pages** marking the stack as **non-executable**, therefore preventing the execution of arbitrary user placed shell code.



Of course just like **SafeSEH** and all the other great security mechanisms implemented this is flawed and can be bypassed using a variety of methods but mainly **ROP / Return-Oriented Programming.** More on ROP later! 



### Page Tables Explained



I feel it's necessary to talk about **Page Tables** & **Memory Management w/ Virtual Address Space** in this article as my research into **ROP** has led me into a lot of articles mentioning things such as **Page Table Entries, Page Table Directories** etc with no explanation supplied. 





#### Virtual Address Space



**Virtual Address Space** is the allocated virtual memory addresses allocated to a process by the CPU upon runtime, this virtual space remains private and mitigates processes leaking into other processes address space unless explicitly shared.  



Each process on a 32-bit Windows has it's own **Virtual Address Space** allocated that allows addressing *upto* 4GB of Memory where as 64-bit Windows allows a whopping allocation of **8 TB** - This addressing has not be be confused with **PAE Mode** which allows an **x86 OS** to interact with more than **4GB Physical Memory**.



**So.... - Why do we need Virtual Address Space?**

















#### Page Table Entries

#### Page Table Directories





### Different Types Modes of DEP



If you have already looked at **EMET GUI** to turn on/off the **DEP** policy you might have noticed there are numerous options to select from, I have listed them below.



- **OptIn**
  - **DEP** is turned on for a limited amount of Applications & Services based on settings.
- **OptOut**
  - **DEP** is turned on for all Applications, Services - *Besides user defined Exceptions*
- **AlwaysOn**
  - **DEP** is turned on for all Applications, Services etc. **No Exceptions**
- **AlwaysOff**
  - **DEP** is turned off indefinitely for *everything*



The *default setting* for the **DEP Policy** is different across every single OS, so I would advise you check out the default policy for your *VM OS* - I have enabled **AlwaysOn** on my *Windows 7 x86 Ultimate VM*.





### How Does DEP Really Work?



So, **Hardware DEP** works by taking advantage of the **NX** **bit** protection aka **No Execution Page Protection** sometimes known as **XD bit / Execute Disabled** by *Intel*. If this bit is set the CPU will mark certain area's of memory such as data, heap, stack or memory pools as **non-executable.**



If we try to execute code from a protected area of memory we will receive an **Access Violation** with error code `STATUS_ACCESS_VIOLATION` - This will probably result in the program either *halting* or more commonly  the process will just terminate. 



As you can see in the picture below I have tried to execute the final `exploit.py` that we crafted in [Part 1](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) However now instead of getting successful execution and receiving a reverse-shell back to our attacker box we are hit with a **Access Violation** - We can also see on the stack that we are sitting in our NOPs above our shellcode as the stack should just contain pointers to instructions which reside in other parts of memory which are executable whereas in this case the stack implicitly contains direct instructions to execute. Even though NOPs are really just `No-Operations` they are still technically treated as instructions. 




<p align = "center">
<img src = "https://i.imgur.com/TQapH2p.png">
</p>



If we wish to use **DEP** (by default in modern systems) the **CPU** must be running in ***PAE Mode / Physical Address Extension*** which is a memory management feature for `x86 Architecture` that allows *x86 CPU's* to access more than 4GB of Physical Memory on capable versions of Windows, Truthfully ***PAE Mode*** is mostly enabled by default out of the box on any modern Intel/AMD (x86/x64) system.



When I was writing this, truthfully I struggled to understand ***PAE Mode*** but looking over the Microsoft official docs helped a bunch, I was able to discover that ***PAE Mode*** allows an operating systems **Page Table Entries (PTE)** & **Page Directory Entries (PDE)** to reference physical memory beyond 4GB - However, this should not be mistaken with virtual address space available to a process. Irrespective of ***PAE Mode*** or not if you are running a 32-bit version of Windows you will be limited to a 4GB **Virtual Address Space**.



Truthfully there is not much need to know the inners and outs of PAE Mode due to the fact if **DEP** is enabled as on, Windows will also automatically enable ***PAE Mode*** itself due to it's dependency. 



**Hardware DEP** relies on processor hardware to explicitly mark memory with an attribute/bit that indicates should not be executed from that memory address/region  - As I have already said **DEP** functions on a per-virtual memory page basis and **DEP** will alter a bit in the **Page Table Entry (PTE)** to mark the memory page as *non-executable*.







It's worth noting that if an application must run code from a memory page it has to be explicitly set with & marked with **PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, or PAGE_EXECUTE_WRITECOPY **when it is allocating the relevant memory. 













## What is ROP (Return-Orientated Programming)? 


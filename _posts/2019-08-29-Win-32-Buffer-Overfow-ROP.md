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



## Different Types & Modes of DEP



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





## Page Tables Explained



I feel it's necessary to talk about **Page Tables** & **Memory Management w/ Virtual Address Space** in this article as my research into **ROP** has led me into a lot of articles mentioning things such as **Page Table Entries, Page Table Directories** etc with no explanation supplied. 





### Virtual Address Space & Page Files



**Virtual Address Space (VAS)** is the allocated virtual memory addresses allocated to a process by the CPU upon process runtime, this virtual space remains private and mitigates processes leaking into other processes address space unless explicitly shared.  



Each process on a 32-bit Windows has it's own **Virtual Address Space** allocated that allows addressing *upto* 4GB of Memory where as 64-bit Windows allows a whopping allocation of **8 TB** - This addressing has not be be confused with **PAE Mode** which allows an **x86 OS** to interact with more than **4GB Physical Memory**.



**So.... - Why do we need Virtual Address Space?**



Well **VAS** is actually a very important component of all operating systems as it allows us to run more applications on the system than we have *physical memory* available for. But how? Well **Virtual Memory** is *simulated memory* that is written to a file on the hard drive and this file is commonly called a **Page File** or **Swap File**



This technology once upon a time did not exist and users had no choice that when they had numerous programs open at once and they ran out of **RAM** they would not be able to open any other applications and would have to prioritize *open applications.*



Now we are still *using* our physical memory aka **RAM** but the **OS** is also mapping **RAM Addresses** to the **HDD** inside a reserved portion which can either by a file or partition itself - Within **Windows** this file is called the `pagefile.sys` aka the **Page File** - I believe in Linux based distros that a separate partition is always created to facilitate this need but truthfully Linux internals is black-magic too me.  



Within Windows the **VAS** & **Page File** settings are managed automatically the OS but you can actually alter the maximum size etc within the *Advanced* options in Control Panel.  






<p align = "center">
<img src = "https://i.imgur.com/5supMDc.png">
</p>





### What is Swapping?



You may have noticed in the **Virtual Address Space** section above I mentioned the **Page File** is sometimes called the **Swap File** - This is due to the the process that occurs related to **VAS** is called **Swapping**



**Swapping** is the process of moving data from **RAM** to **Disk** **(Page File)** and back from **Disk** to **RAM** - This is all centrally managed by the **Virtual Memory Manager (VMM)**. As I am sure you know the Disk is typically a lot slower than **RAM** - And that is where this efficient process comes into play. 



Let me give an example of the **Swapping** process taking place; Let's imagine we open 2 x applications (**Application 1** & *Application 2*) and we only have enough space in the physical memory to facilitate one application, let's say **Application 1** & let's say we are *using* **Application 1** & *Application 2* is simply backgrounded/minimized.



The **VMM** will now place all of **Application 1's** into RAM due to the fact that it's being actively used and it will place all of *Application 2's* into the **Page File / Virtual Memory** stored locally on the **Disk**



Now let's say we decide to start use *Application 2* & minimize **Application 1**, the **VMM** will now spring into action and swap **Application 1** straight from **RAM** into the **Page File** stored locally on the **Disk** & vise versa in which it will move *Application 2* from the **Page File** into **RAM** 



These actions of **RAM** -> **Disk** or **Disk** -> **RAM** are actually *subprocesses* of Paging and each have a name respective of direction, for example:

- **RAM** -> **Disk** 

  - Paging Out

- **Disk** -> **RAM**
  
  - Paging In
  
  


The happens to ensure that the application which is being used is being prioritized in terms of performance and is always running in **RAM**



Now we have covered **Virtual Address Space** & how the utilize **Page Files** - We should now go into specifics about the Page File & Table's to further understand.





### Pages, & Page Tables



Currently basically all implementations of **Virtual Address Space** divide a specified *address space* into **Pages** - These pages are blocks of continuous **Virtual Memory Addresses**.



These "blocks" or **Virtual Memory Addresses** then form what we called a **Page Table** - These tables are then used too effectively translate the **Virtual Memory Addresses** into **Physical Addresses** & provide a mapping between **Virtual Addresses (VA)** and **Physical Addresses.** 

Within each **Page Table** there will be an attribute which specifies if the **Page Table** corresponds to real memory or virtual memory.





Soooo... Why are we even talking about **Pages & Page Tables** when we're focusing on **DEP & ROP** - Well without going into too much detail here as I have talked about it under the `How Does DEP Really Work` section, there are numerous entries/bits (**Page Table Entries**) within the **Page Table** which dictate the security mechanisms for the relevant **Page / Memory Page**



Here is an example **Page Table Entry** that would be stored in a **Page Table**.


<p align = "center">
<img src = "https://i.imgur.com/tZgGOsp.png">
</p>

Each Square / Color here represents a `bit` or a status bit which can contain a small value with information about the **Page Table Entry**



- **Frame Number**

  - Provides the number aka **Frame Number** for the relevant Page

- **Present / Absent**

  - This `bit` says whether the page you are looking for is present or not, If it is not present this would initiate a **Page Fault** 

- **Protection Bit**

  - This is the part that interests us in this article, this is the `bit` which references the relevant protection associated with the Page, I believe by default this will contain the `NX` bit.

- **Reference**

  - Will state if the **Page** has been referred to in the last clock cycle or not

    

    

    

    

    

     

## How Does DEP Really Work?



So, **Hardware DEP** works by taking advantage of the **NX** **bit** protection aka **No Execution Page Protection** sometimes known as **XD bit / Execute Disabled** by *Intel*. If this bit is set the CPU will mark certain area's of memory such as data, heap, stack or memory pools as **non-executable.**



If we try to execute code from a protected area of memory we will receive an **Access Violation** with error code `STATUS_ACCESS_VIOLATION` - This will probably result in the program either *halting* or more commonly  the process will just terminate. 



As you can see in the picture below I have tried to execute the final `exploit.py` that we crafted in [Part 1](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) However now instead of getting successful execution and receiving a reverse-shell back to our attacker box we are hit with a **Access Violation** - We can also see on the stack that we are sitting in our NOPs above our shellcode as the stack should just contain pointers to instructions which reside in other parts of memory which are executable whereas in this case the stack implicitly contains direct instructions to execute. Even though NOPs are really just `No-Operations` they are still technically treated as instructions. 




<p align = "center">
<img src = "https://i.imgur.com/TQapH2p.png">
</p>



If we wish to use **DEP** (by default in modern systems) the **CPU** must be running in ***PAE Mode / Physical Address Extension*** which is a memory management feature for `x86 Architecture` that allows *x86 CPU's* to access more than 4GB of Physical Memory on capable versions of Windows, Truthfully ***PAE Mode*** is mostly enabled by default out of the box on any modern Intel/AMD (x86/x64) system.



When I was writing this, truthfully I struggled to understand ***PAE Mode*** but looking over the Microsoft official docs helped a bunch, I was able to discover that ***PAE Mode*** allows an operating systems **Page Table Entries (PTE)** & **Page Directory Entries (PDE)** to reference physical memory beyond 4GB - However, this should not be mistaken with virtual address space available to a process. Irrespective of ***PAE Mode*** or not if you are running a 32-bit version of Windows you will be limited to a 4GB **Virtual Address Space**.



Honestly there is not much need to know the inners and outs of PAE Mode due to the fact if **DEP** is enabled as on, Windows will also automatically enable ***PAE Mode*** itself due to it's dependency. 



**Hardware DEP** relies on processor hardware to explicitly mark memory with an attribute/bit that indicates should not be executed from that memory address/region  - As I have already said **DEP** functions on a per-virtual memory page basis and **DEP** will alter a bit in the **Page Table Entry (PTE)** called the **Protection Bit** to mark the memory page as *non-executable*.



It's worth noting that if an application must run code from a memory page it has to be explicitly set with & marked with **PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, or PAGE_EXECUTE_WRITECOPY **when it is allocating the relevant memory. 



















# Bypass Methods



Now we have a solid understanding of how **DEP** works and some of the internals of Windows & Memory Management I would like to discuss the various methods we can employ as an attacker to circumvent **Data Execution Protection (DEP)**.



I will first talk about the old-school **return-2-libc** method and later talk about What is **Return-Orientated Programming** and how we can use it to bypass **DEP** 







## Return-2-Libc Method



http://www.phearless.org/istorija/razno/win-ret-into-libc.txt



The return-2-libc technique is something that confused me for a very long time despite a lot of reading but if you actually just read it out loud `Return-2-libc` and realize that all we are doing is `returning` to a library instead of something like a **JMP ESP** function we will see are effectively just returning to a function contained inside a a externally imported **DLL**  or library on Linux. 



For example we would overrun our **return-address** with the location or some system function or Win32 API call in Windows from a **DLL** - A common function used in this case on Win32 is the `WinExec()` function which would allow us to spawn & execute the `cmd.exe` process. 





Add this to table alognside other article on work computer showing API calls

- **VirtualAlloc(MEM_COMMIT + PAGE_READWRITE_EXECUTE)** + copy memory.  This will allow you to create a new executable memory region, copy your shellcode to it, and execute it. This technique may require you to chain 2 API’s into each other.
- **HeapCreate**(HEAP_CREATE_ENABLE_EXECUTE) + HeapAlloc() + copy memory. In essence, this function will provide a very similar technique as VirtualAlloc(), but may require 3 API’s to be chained together))
- **SetProcessDEPPolicy()**. This allows you to change the DEP policy for the current process (so you can execute the shellcode from the stack) (Vista SP1, XP SP3, Server 2008, and only when DEP Policy is set to OptIn or OptOut)
- **NtSetInformationProcess()**.  This function will change the DEP policy for the current process so you can execute your shellcode from the stack.
- **VirtualProtect(PAGE_READ_WRITE_EXECUTE)**. This function will change the access protection level of a given memory page, allowing you to mark the location where your shellcode resides as executable.
- **WriteProcessMemory().** This will allow you to copy your shellcode to another (executable) location, so you can jump to it and execute the shellcode. The target location must be writable and executable.





##  What is ROP (Return-Orientated Programming) ? 
---
title: Win32 Buffer Overflow - SEH & Egghunters
tags:[Buffer Overflow,Exploit Development,Windows,]
published: false
---



# [](#header-1)Win32 Buffer Overflow - SEH & Egghunters



## [](#header-2) Introduction



I recently wrote a tutorial on Simple Win32 Buffer-Overflows where we exploited one of the most simple Buffer Overflows around; **Stack-Overflow** aka **EIP Overwrite** which you can read here -> -linkhere-



At the start of the article I discussed how I recently embarked on a mission to learn exploit development better and the purpose of this mini-series was too have reason to put pen to paper and finally learn all this shit :) - Now in this article I want to move on a little bit from basic **Stack Overflows** and progress to **SEH - Structured Exception Handling** Overflows. 



Now of course it is fairly obvious that the exploits I am talking about here are fairly old, think *WinXP* days and a lot of this stuff has been mitigated with new technologies such as **DEP / ASLR** etc, but as I said in Part-1 you have to learn the old stuff before you learn the new stuff. 



Let's jump right into it. 





## [](#header-2) Exception Handlers 101



Before we jump into looking at this from a exploitation perspective let's first talk about what **Exception Handlers** *really are*, the different ypes and what purpose they service within the Windows OS. 



#### [](#header-4) What is an Exception?



*An exception is an event that occurs during the execution of a program/function*



#### [](#header-4) Different Types of Handlers



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



The above example represents a basic exception handler in `C#`



Now it is not uncommon for software developers to write there own exception handlers to manage any errors/wanrings there software may through but **Windows** also has one built in called **Structured Exception Handler (SEH)** which can throw up error messages such as `Program.exe has stopped working and needs to close` - I'm sure you have all seem them before. 



So, How do they work? Well as we know when an application is executed and each respective **function** is ran from within *the application* there is a **stack-frame** created before finally being ***popped*** off after the function *returns* or finishes executing.  Now the same is actually true for **Exception Handlers** (kinda?) Basically if you run a function with a **Exception Handler** embedded in itself- that exception handler will also get it's own dedicated **stack-frame** - This is where the problem lies - the exception-handlers are pushed onto the stack so therefore could be overwritten and controlled by a malicious user.




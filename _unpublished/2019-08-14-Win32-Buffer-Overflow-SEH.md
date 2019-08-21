---
title: Win32 Buffer Overflow - SEH & Egghunters
tags: [Buffer Overfow,Exploit Development,Windows,SEH,Egghunting]
description: I have recently embarked on the task of understanding Buffer Overflows beyond simple Stack Overflows and I figured the best way to go about it was to go back to the start, recover Stack/Assembly principles. Quickly recover simple Stack Overflows and then begin writing a blog post for each relevant area that I want to learn in greater detail.
published: true
---









# [](#header-1)Win32 Buffer Overflow Pt2 - SEH & Egghunters



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



The above example represents a basic exception handler **(EH)** in `C#` implemented by the developer - Sometimes looking at code like above can be quite scary to a non-programmer but all we are really doing is saying `try` run this piece of code & if an error/exception occurs do whatever the `catch` block contains. Simple!



Now it is not uncommon for software developers to write there own exception handlers to manage any errors/warnings there software may through but **Windows** also has one built in called **Structured Exception Handler (SEH)** which can throw up error messages such as `Program.exe has stopped working and needs to close` - I'm sure you have all seem them before. 



It is also worth mentioning that no matter where the **Exception Handler** is defined whether it be at the **OS-Level** and/or **Developer Level** that all **Handlers** are controlled and managed centrally and consistently by the **Windows SEH** via a collection of designated memory locations and *functions*.




#### [](#header-4) So How Do Structured Exception Handlers Work?



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



#### [](#header-4) The Vulnerability



So to just recap, we have covered what exceptions are, the different types of handlers and we have also spoken about how **Structured Exception Handlers** *really* work, so now we should probably talk about this from an attackers point of view and how we can exploit these handlers to gain control over a programs execution flow similar to the `EIP Overwrite` in Part 1.



Now in Part 1 [Here](https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html) - We were able to control the *execution flow* over VulnServer & SLMail to redirect it too our own *shellcode* and pop a reverse shell, now of course this was a really old vulnerability and SEH was supposed to resolve this but it was a really poor implementation and soon exploited itself. 











## [](#header-2) Egghunters 101





***



# [](#header-1) Examples



## [](#header-2) VulnServer


## [](#header-2) BigAnt Server
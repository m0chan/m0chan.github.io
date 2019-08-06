---
title: Generic Cheatsheet
tags:[Cheatsheet,Linux,Windows,Web App,Fuzzing]
published: true
---


# [](#header-1)Generic Cheatsheet

A place for me to store my tips/tricks and commands on things that aren't directly bound to Windows (or) Linux

## [](#header-2) Fuzzing


### [](#header-3) Sub Domain

```bash
wfuzz -c -f re -w /SecLists/Discovery/DNS/subdomains-top1mil-5000.txt -u "http://domain.htb" -H "Host: FUZZ.domain.htb" --hh 311\
```
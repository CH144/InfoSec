---
layout: wrapper
title: ROP Primer
---

### Return-oriented programming (ROP)
ROP is an attack which gets around `NX` by reusing legitimate code in the binary or libc that is already marked as executable. Examples:
- `ret2win`
- `ret2libc`
- `ret2syscall`
- `ret2dlresolve`
- `ret2csu`
- `SROP`

### Looking for gadgets
Ideally, gadgets should only perform the intended behaviour (e.g. setting a specific register) without side effects (e.g. setting unrelated registers), but this is not always possible.

In order to use these gadgets, either the address needs to be static, or there is an address disclosure vulnerability, or bruteforce the lower nibbles. `PIE` protects the binary, while `ASLR` protects libc.

[ropper](https://github.com/sashs/Ropper) is a tool that can be used to look for useful gadgets:
1. `ropper`
2. `file vuln` or `file libc.so.6`
3. `search pop rax`

[one_gadget](https://github.com/david942j/one_gadget/releases) is a tool that can be used to look for gadgets in libc which can immediately grant a shell. Particularly useful if the overwrite is limited (e.g. minimal overflow, or targeting a GOT entry). However, each `one_gadget` has its own constraints to work, and sometimes none may work.

### Checking for functions
Sometimes, useful functions can be found, such as `open()` and `sendfile()`. Such cases can simplify paths of attack.

Othertimes, useful functions _cannot_ be found, such as `puts()`. Such cases close off certain paths of attack.

### Stack alignment
Sometimes, things break if the stack is not 16-byte aligned when performing a call. In such cases, use a `ret` gadget to align the stack before calling the next item in the chain.

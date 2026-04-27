---
layout: wrapper
title: Using Checksec
---

### Usage of pwntools' checksec
```bash
checksec vuln
```

### Architecture
`x32`: addresses are 4 bytes; arguments passed on the stack

`x64`: addresses are 8 bytes; arguments passed via registers

### RELRO
full: the GOT is read-only

partial: the GOT is writable; allowing the executed function to be changed
- example 1: change `__stack_chk_fail` to `main`
- example 2: change `exit` to `one_gadget`

### Stack canary
present: BOF is not trivial
- leak the canary (e.g. format string read)
- overwrite the return address directly (e.g. format string write, `strcpy`)

absent: BOF is trival

### NX
present: unlikely to be a ret2shellcode, unless there is a way to make the stack executable

absent: possibly a ret2shellcode

### PIE
present: may require a binary address leak, or brute-force the fouth nibble (`0x?000`)

absent: address of ROP gadgets, functions, global variables, are static

### Stripped
yes: no symbol names, harder debugging

no: symbol names known, easier debugging

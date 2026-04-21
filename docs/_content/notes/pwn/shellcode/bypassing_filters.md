---
layout: wrapper
title: Bypassing Filters
---

## Avoiding marker for x64 instructions (`48`)
### Using load effective address (`lea`)
```
mov rbx, 0x67616c662f => lea edi, [eip+flag]
push rbx                 flag:
mov rdi, rsp             .string "/flag"
```

### Zeroing with `xor` instead of `mov`
```
mov rsi, 0 => xor esi, esi
```

### Zeroing the `rdx` register with special instructions
`cdq`: Takes value of bit 31 of `eax` and copies it to `edx` with zero extends

### Using `push` and `pop` instead of `mov`
```
mov rsi, rax => push rax
                pop rsi
```

## Avoiding `syscall` (`0f05`), `sysenter` (`0f34`), `int 80` (`80cd`)
### Self-modification
```
syscall => mov byte ptr [rip+sys], 0xf
           mov byte ptr [rip+sys+1], 0x5
           sys:
           .short 0
```

## Avoiding bad regions
```
    jmp continue
    .rept 0xb
        nop
    .endr
continue:
```

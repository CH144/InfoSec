---
layout: wrapper
title: Tcache Safe Linking
---

## glibc 2.32~
### Leaking the heap address
```python
def protect(pos, ptr):
    return (pos >> 12) ^ ptr

def reveal(pos, ptr):
    return protect(pos, ptr)

malloc(0, 16)
malloc(1, 16)
free(1)
free(0)
heap = reveal(puts(1) << 12, puts(0)) - 0x20
```

### Alternative `reveal`
```python
def reveal(leak):
    for i in range(8):
        leak ^= (leak >> 12) & (0xff00000000000000 >> i * 8)
    return leak
```

### 16-byte alignment
The last digit of the hex address for an allocation must be 0.

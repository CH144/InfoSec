---
layout: wrapper
title: Tcache Vulnerabilities
---

### Use-after-free (UAF)
1. Read-after-free: data leakage, user-data corruption
2. Write-after-free: metadata corruption

### Leakage: heap address
1. two chunks of equal sizes are freed
2. more recently freed chunk is read: leaks `next`

### Leakage: sensitive data I
1. a chunk of certain size is freed
2. the same chunk is allocated due to suitable size
3. sensitive data is written to this chunk
4. the pointer is read again

### Leakage: sensitive data II
1. an address has sensitive data
2. tcache poisoning is performed, but the allocation is discarded
3. the sensitive data was written to `head` during the allocation
4. a subsequent free will write the sensitive data to `next`

### Corruption: user-data
1. `free`: first 8 bytes are now `next`, second 8 bytes are now `key`
2. `malloc`: `next` is not cleared, `key` is cleared to NULL
3. secrets checks that depend on these 16 bytes will be affected
4. if tcache poisoning is possible, secrets can strategically be NULLed out
5. the corruption happens regardless of whether the allocation is discarded

### Corruption: metadata
#### Tcache poisoning: pointer to anywhere
1. allocate the same size to two pointers
2. free both pointers
3. corrupt `next` of the more recently freed pointer
4. allocate the same size twice

```
before [head:B]->[next:A]->[next:NULL]
after  [head:B]->[next:TARGET]->[next:???]
```

#### Double-free
1. a pointer is freed
2. corrupt `key`
3. the pointer can be freed again
4. tcache poisoning can be done as described above

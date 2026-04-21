---
layout: wrapper
title: Tcache Primer
---

### Storage
1. The tcache has 64 bins of various sizes (16 to 1032) that store chunks of the same size.
2. Freed chunks of the same bin are stored using a singly linked-list.
3. Newly freed chunks are added to the 'front' of the LL.

```
Before frees
[head:NULL]

After free(A)
[head:A]->[next:NULL]

After free(B)
[head:B]->[next:A]->[next:NULL]
```

### Structure
1. The second 8 bytes before writable memory indicates the size of the previous chunk.
2. The first 8 bytes before writable memory indicates the size of the chunk and includes 3 flag bits.
3. The first 8 bytes of writable memory is used for the `next` pointer when freeing.
4. The second 8 bytes of writable memory is used for the `key` when freeing.
5. The `key` is cleared when the chunk is re-allocated.

### Chunk layout
```
           -16     -9 -8 -1  0  7  8 15
Freed:     [prev size][size][next][key]
Allocated: [prev size][size][user data]
```

### Overlapping metadata
```
 malloc(0x10)             malloc(0x10)

[p.size][size][0 7][8 15][p.size][size][0 7][8 15]
```
```
[p.size][size][0 7][8 15][16  23]
                         [p.size][size][0 7][8 15]

 malloc(0x18)             malloc(0x10)
```

### Defense
Double-free: the tcache detects double free only by checking the key.

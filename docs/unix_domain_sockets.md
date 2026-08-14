## Unix-domain sockets
+ Sockets that are used for communication between processes running on the same system

### Resources
+ `SCM_RIGHTS` and garbage collection: https://lwn.net/Articles/779472/

### Reference counts for file structures
+ Every open file descriptor in user space is represented by a file structure in the kernel
+ file structures can have multiple references to them at any given time
    + e.g `dup` allocates a second file descriptor referring to the same file structure, increasing reference counter
    + `close` or `exit` decrease reference counter
+ kernel must keep track of references to a file structure to be able to safely free it once reference count reaches 0
    + refcount held in `f_count` field

**Reference cycle**
+ A group of objects reference each other in a cycle, e.g. `A → B → A`, so each object is indirectly referenced by itself.
+ **When cycles become a problem**: A reference cycle becomes a problem when no external references remain that could break it. The objects in the cycle keep each other’s reference counts above 0 and therefore cannot be freed.

### SCM_RIGHTS
+ control message used to transmit an open file descriptor from one process to another
+ creates a copy of the file descriptor which also creates a new reference to underlying file structure
    + **reference is attached to receiving end of the socket**, such that sending side can immediately close its file descriptor even when the receiver hasn't received it yet.
    + reference is needed to keep the file open for as long as it takes the receiving end to accept the new file and take ownership of the reference

**Cycle creation**
+ The way `SCM_RIGHTS` works has important side effects that could create reference cycles: a file structure representing the receiving end of an `SCM_RIGHTS` message, in essence, owns a reference to the file structure transferred in that message until the application accepts it.
    + When sending a file descriptor to a socket, the `struct file` representing the receiving socket indirectly holds a reference to the `struct file` being transferred, via the socket’s receive queue.
+ cycle creation example:
    + process connects to itself using unix domain sockets. Has two FDs: `fd1`, `fd2`
    + Now uses `SCM_RIGHTS` to send `fd1` to `fd2` and the reverse
    + Now, due to how `SCM_RIGHTS` work, the file structure at each end of the socket indirectly holds a reference to the other
    + If, the process then closes `fd1` and `fd2` without accepting the transferred file descriptors, it will remove the only two references to the underlying file structures — except for those that make up the cycle itself => **unbreakable cycle is created** 

unbreakable cycle example:
```
external refs: none

fd1 --strong ref--> fd2
^                |
|----strong ref--|
```

### AF_UNIX garbage collector
+ `unix_gc()` in `net/unix/garbage.c`
+ goal is to identify and break cycles of AF_UNIX sockets whose remaining references are entirely internal/in-flight `SCM_RIGHTS` references
    + i.e. no external references

**origin of vulnerabilities**: 
+ issues arise whenever the GC reasoning breaks down and the GC mistakenly frees a cycle that still has external references
    + GC mistakenly concludes “these references are only part of an unreachable cycle” when an external/live reference actually still exists → objects/messages can be freed prematurely → potentially UAF / kernel memory corruption.

**Past CVEs**
+ CVE-2025-40214: incorrect SCC bookkeeping (`scc_index`) makes the GC classify an alive socket as garbage and garbage-collect its receive queue.
+ CVE-2026-53361: a race leaves `gc_in_progress == false` while GC is actually running; MSG_PEEK can then modify the relevant reference state in a way the GC does not account for correctly.

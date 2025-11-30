## Technique
+ https://faith2dxy.xyz/2025-11-28/extending_race_window_fallocate/

### Steps
1. Opening `/dev/shm` and passing the FD to `fallocate()` calls `shmem_fallocate()`.
2. The `FALLOC_FL_PUNCH_HOLE` flag causes `shmem_fallocate()` to unmap the address range allocated by the first `fallocate()` call, as well as deallocate the actual physical pages back to the system. This takes a not-insignificant amount of time.
3. If a page fault occurs concurrently during this unmap and deallocation process (for example, when `buf` is accessed in `main()`), `shmem_fault()` is called.
4. If `shmem_fault()` notices that `fallocate()` is in the middle of a hole punch, it calls `shmem_falloc_wait()`, which sleeps and waits for the hole punching to finish.

**Condition**
+ Need access to userspace address inside race window

**Usage**
+ Just exchange the access to `buf` in the poc with an actual access from kernel space
